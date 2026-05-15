import discord
from discord.ext import commands
from discord import app_commands

import aiohttp
import easyocr
import numpy as np
from PIL import Image, ImageChops
import io
import re
import json
import asyncio
import warnings
import hashlib
import os
import logging
from pathlib import Path
from functools import partial
from dotenv import load_dotenv
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import imagehash
from typing import Optional, List

warnings.filterwarnings("ignore")
load_dotenv()

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("discord_bot")

# কনফিগ ফাইল
CONFIG_FILE = Path("config.json")
HASH_DB_FILE = Path("scam_hashes.json")
USER_WARNINGS_FILE = Path("warnings.json")

DEFAULT_CONFIG = {
    "delete_messages": True,
    "log_channel_id": None,
    "ignored_roles": [],
    "blocked_server_names": ["cracked vault"],
    "scam_keywords": [
        "withdrawal success",
        "rackswin",
        "claim your reward",
        "crypto casino",
        "giving away \\$",
        "vyro project",
        "free.*usdt",
        "withdrawal of \\$.*was success",
    ],
    "auto_ban_after_warnings": 3,
    "scan_all_channels_interval": 3600,
    "phishing_domains": [
        "discord-nitro",
        "steamcommunity",
        "discord-gift",
    ],
    "url_whitelist": [
        "discord.com",
        "discord.gg",
        "youtube.com",
        "tenor.com",
        "imgur.com",
    ],
    "max_warnings_before_mute": 5,
    "mute_duration_hours": 24,
    "suspicious_account_age_days": 7,
    "spam_threshold": 5,  # 5 messages
    "spam_interval": 10,  # in 10 seconds
    "bad_words": ["scam", "fake", "hack"],
    "welcome_channel_id": None,
    "auto_role_id": None,
}

MAX_IMAGE_SIZE = 8 * 1024 * 1024
OCR_MAX_DIMENSION = 900
OCR_CONCURRENCY = 2
OCR_CACHE_LIMIT = 1000

# রেজেক্স প্যাটার্ন
INVITE_RE = re.compile(r"discord(?:\.gg|app\.com/invite)/([a-zA-Z0-9\-]+)")
URL_RE = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<]*")
SUSPICIOUS_TEXT = ("$", "crypto", "usdt", "btc", "withdraw", "claim", "cashout", "casino", "free nitro", "gift")

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

def load_json_file(filepath, default={}):
    if filepath.exists():
        return json.loads(filepath.read_text(encoding="utf-8"))
    filepath.write_text(json.dumps(default), encoding="utf-8")
    return default.copy()

def save_json_file(filepath, data):
    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")

config = load_config()
compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in config["scam_keywords"]]
scam_hash_database = load_json_file(HASH_DB_FILE, {"hashes": [], "image_hashes": []})
user_warnings = load_json_file(USER_WARNINGS_FILE, {})

# OCR মডেল
logger.info("Loading OCR model...")
ocr = easyocr.Reader(["en"], gpu=False, verbose=False, detector=True, recognizer=True)
logger.info("OCR Ready.")

ocr_semaphore = asyncio.Semaphore(OCR_CONCURRENCY)
ocr_cache = OrderedDict()

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.members = True
intents.moderation = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
http_session = None
spam_control = {}  # {user_id: [timestamps]}

class SecurityLevel:
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# ইমেজ হ্যাশ চেক
def get_image_hash(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return str(imagehash.average_hash(img))
    except:
        return None

def get_perceptual_hash(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return str(imagehash.phash(img))
    except:
        return None

# ফিশিং ইউআরএল ডিটেকশন
def check_phishing_url(url):
    url_lower = url.lower()
    
    # ফিশিং ডোমেইন চেক
    for domain in config["phishing_domains"]:
        if domain in url_lower and not any(wl in url_lower for wl in config["url_whitelist"]):
            return True
    
    # সন্দেহজনক URL প্যাটার্ন
    suspicious_patterns = [
        r"discord.*nitro.*free",
        r"steam.*free.*gift",
        r"claim.*discord.*nitro",
        r"verify.*account.*discord",
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url_lower):
            return True
    
    # URL শর্টনার ডিটেক্ট
    shorteners = ["bit.ly", "tinyurl", "shorturl", "goo.gl", "t.co"]
    if any(s in url_lower for s in shorteners):
        return True
    
    return False

# অ্যাকাউন্ট এজ চেক
def check_account_age(member, days=7):
    account_age = (datetime.now(timezone.utc) - member.created_at).days
    return account_age < days

# OCR কাজ
def _ocr(image_bytes):
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    
    if max(img.size) > OCR_MAX_DIMENSION:
        ratio = OCR_MAX_DIMENSION / max(img.size)
        img = img.resize((int(img.width * ratio), int(img.height * ratio)))
    
    img = np.array(img)
    result = ocr.readtext(img, detail=0, paragraph=True, decoder="greedy", beamWidth=1)
    return " ".join(result).lower()

async def run_ocr(image_bytes):
    digest = hashlib.md5(image_bytes).hexdigest()
    
    if digest in ocr_cache:
        return ocr_cache[digest]
    
    async with ocr_semaphore:
        try:
            loop = asyncio.get_event_loop()
            text = await loop.run_in_executor(None, partial(_ocr, image_bytes))
        except Exception as e:
            print(f"OCR failed: {e}")
            text = ""
    
    ocr_cache[digest] = text
    if len(ocr_cache) > OCR_CACHE_LIMIT:
        ocr_cache.popitem(last=False)
    
    return text

# স্ক্যাম চেক (মাল্টি-লেভেল)
async def advanced_scam_check(message, text, image_bytes=None):
    threats = []
    security_level = SecurityLevel.LOW
    
    # টেক্সট বেসড চেক
    for pattern in compiled_scam_patterns:
        if pattern.search(text):
            threats.append(f"Scam Pattern: {pattern.pattern}")
            security_level = max(security_level, SecurityLevel.HIGH)
    
    # URL চেক
    urls = URL_RE.findall(message.content)
    for url in urls:
        if check_phishing_url(url):
            threats.append(f"Phishing URL: {url}")
            security_level = max(security_level, SecurityLevel.CRITICAL)
    
    # ইমেজ হ্যাশ চেক
    if image_bytes:
        img_hash = get_image_hash(image_bytes)
        phash = get_perceptual_hash(image_bytes)
        
        if img_hash and img_hash in scam_hash_database.get("hashes", []):
            threats.append("Known scam image hash")
            security_level = max(security_level, SecurityLevel.CRITICAL)
        
        if phash and phash in scam_hash_database.get("image_hashes", []):
            threats.append("Similar to known scam image")
            security_level = max(security_level, SecurityLevel.HIGH)
    
    # সন্দেহজনক অ্যাকাউন্ট চেক
    if check_account_age(message.author, config.get("suspicious_account_age_days", 7)):
        if security_level >= SecurityLevel.MEDIUM:
            threats.append("New account + suspicious content")
            security_level = SecurityLevel.HIGH
    
    return threats, security_level

# ওয়ার্নিং সিস্টেম
async def add_warning(user_id, reason):
    user_id = str(user_id)
    if user_id not in user_warnings:
        user_warnings[user_id] = {
            "count": 0,
            "warnings": [],
            "last_warning": None
        }
    
    user_warnings[user_id]["count"] += 1
    user_warnings[user_id]["warnings"].append({
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    user_warnings[user_id]["last_warning"] = datetime.now(timezone.utc).isoformat()
    
    save_json_file(USER_WARNINGS_FILE, user_warnings)
    
    return user_warnings[user_id]["count"]

# ভায়োলেশন হ্যান্ডলিং (অ্যাডভান্সড)
async def handle_violation(message, reason, security_level=SecurityLevel.MEDIUM):
    deleted = False
    
    # মেসেজ ডিলিট
    if config["delete_messages"]:
        try:
            await message.delete()
            deleted = True
        except:
            pass
    
    # ওয়ার্নিং অ্যাড
    warning_count = await add_warning(message.author.id, reason)
    
    # অ্যাকশন টেকেন
    action_taken = []
    
    try:
        # ইউজারকে নোটিফাই
        embed = discord.Embed(
            title="⚠️ Security Alert",
            description=f"Your message in **{message.guild.name}** was flagged by our security system.",
            color=discord.Color.orange()
        )
        embed.add_field(name="Channel", value=f"#{message.channel.name}", inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Warning", value=f"{warning_count}/{config.get('max_warnings_before_mute', 5)}", inline=True)
        embed.set_footer(text="If you believe this is a mistake, please contact a moderator.")
        
        await message.author.send(embed=embed)
    except:
        action_taken.append("Could not DM user")
    
    # অটো-মিউট
    if warning_count >= config.get("max_warnings_before_mute", 5):
        try:
            duration = timedelta(hours=config.get("mute_duration_hours", 24))
            await message.author.timeout(duration, reason="Exceeded maximum warnings")
            action_taken.append("User timed out")
        except:
            action_taken.append("Could not timeout user")
    
    # অটো-ব্যান (ক্রিটিকাল)
    if security_level == SecurityLevel.CRITICAL or warning_count >= config.get("auto_ban_after_warnings", 3):
        try:
            await message.author.ban(reason=f"Security threat: {reason}", delete_message_days=1)
            action_taken.append("User banned")
            
            # ব্যান নোটিফিকেশন
            ban_embed = discord.Embed(
                title="🚫 User Banned",
                description=f"{message.author.mention} has been banned for security violation.",
                color=discord.Color.red()
            )
            ban_embed.add_field(name="User", value=f"{message.author} ({message.author.id})")
            ban_embed.add_field(name="Reason", value=reason)
            ban_embed.add_field(name="Warning Count", value=str(warning_count))
            
            if config.get("log_channel_id"):
                log_ch = bot.get_channel(int(config["log_channel_id"]))
                if log_ch:
                    await log_ch.send(embed=ban_embed)
        except:
            action_taken.append("Could not ban user")
    
    # লগিং
    logger.info(f"Violation: {message.author} in {message.channel} - Reason: {reason} - Level: {security_level}")
    log_id = config.get("log_channel_id")
    if log_id:
        log_ch = bot.get_channel(int(log_id))
        if log_ch:
            embed = discord.Embed(
                title="🔒 Security Violation Detected",
                color=discord.Color.red() if security_level >= SecurityLevel.HIGH else discord.Color.yellow()
            )
            embed.add_field(name="User", value=f"{message.author.mention} (`{message.author.id}`)", inline=False)
            embed.add_field(name="Channel", value=message.channel.mention, inline=False)
            embed.add_field(name="Reason", value=f"`{reason}`", inline=False)
            embed.add_field(name="Security Level", value=str(security_level), inline=True)
            embed.add_field(name="Warning Count", value=str(warning_count), inline=True)
            embed.add_field(name="Deleted", value="Yes" if deleted else "No", inline=True)
            embed.add_field(name="Actions", value=", ".join(action_taken) if action_taken else "None", inline=False)
            embed.set_footer(text=f"Message ID: {message.id}")
            
            if message.content:
                embed.add_field(name="Message Content", value=message.content[:1024], inline=False)
            
            await log_ch.send(embed=embed)

# /fullscan কমান্ড - সম্পূর্ণ চ্যানেল স্ক্যান
async def full_scan_channel(channel, limit=None, delete_scams=True, scan_embeds=True):
    found = 0
    scanned = 0
    deleted = 0
    users_warned = set()
    
    try:
        # চ্যানেল হিস্ট্রি স্ক্যান
        async for msg in channel.history(limit=limit or 10000):
            if msg.author.bot:
                continue
            
            message_flagged = False
            
            # টেক্সট চেক
            text_content = msg.content.lower()
            if msg.content:
                # URL চেক
                urls = URL_RE.findall(msg.content)
                for url in urls:
                    if check_phishing_url(url):
                        await handle_violation(msg, f"Phishing URL in message: {url}", SecurityLevel.CRITICAL)
                        found += 1
                        users_warned.add(msg.author.id)
                        message_flagged = True
                        break
                
                # টেক্সট স্ক্যাম চেক
                if not message_flagged:
                    for pattern in compiled_scam_patterns:
                        if pattern.search(msg.content.lower()):
                            await handle_violation(msg, f"Scam pattern in text: {pattern.pattern}", SecurityLevel.HIGH)
                            found += 1
                            users_warned.add(msg.author.id)
                            message_flagged = True
                            break
            
            # অ্যাটাচমেন্ট/ইমেজ চেক
            if msg.attachments and not message_flagged:
                for att in msg.attachments:
                    if not (att.content_type or "").startswith("image/"):
                        continue
                    if att.filename.lower().endswith(".gif"):
                        continue
                    if att.size > MAX_IMAGE_SIZE:
                        continue
                    
                    try:
                        image_bytes = await fetch_bytes(att.url)
                        text = await run_ocr(image_bytes)
                        
                        threats, level = await advanced_scam_check(msg, text, image_bytes)
                        
                        if threats:
                            reason = " | ".join(threats)
                            await handle_violation(msg, reason, level)
                            found += 1
                            users_warned.add(msg.author.id)
                            message_flagged = True
                            
                            # স্ক্যাম ইমেজ হ্যাশ ডাটাবেসে অ্যাড
                            img_hash = get_image_hash(image_bytes)
                            if img_hash:
                                if "hashes" not in scam_hash_database:
                                    scam_hash_database["hashes"] = []
                                if img_hash not in scam_hash_database["hashes"]:
                                    scam_hash_database["hashes"].append(img_hash)
                                    save_json_file(HASH_DB_FILE, scam_hash_database)
                    except:
                        continue
            
            # এমবেড চেক
            if scan_embeds and msg.embeds and not message_flagged:
                for embed in msg.embeds:
                    embed_text = ""
                    if embed.title:
                        embed_text += embed.title + " "
                    if embed.description:
                        embed_text += embed.description + " "
                    
                    if embed_text:
                        for pattern in compiled_scam_patterns:
                            if pattern.search(embed_text.lower()):
                                await handle_violation(msg, f"Scam in embed: {pattern.pattern}", SecurityLevel.HIGH)
                                found += 1
                                users_warned.add(msg.author.id)
                                message_flagged = True
                                break
            
            scanned += 1
            
            # প্রতি 100 মেসেজে প্রোগ্রেস রিপোর্ট
            if scanned % 100 == 0:
                logger.info(f"Scanned {scanned} messages in #{channel.name}... Found {found} violations")
    
    except discord.Forbidden:
        logger.error(f"No permission to read {channel.name}")
    except Exception as e:
        logger.error(f"Error scanning {channel.name}: {e}")
    
    return scanned, found, len(users_warned)

async def fetch_bytes(url):
    async with http_session.get(url) as r:
        return await r.read()

async def resolve_invite_name(code):
    try:
        async with http_session.get(f"https://discord.com/api/v10/invites/{code}") as r:
            if r.status != 200:
                return None
            data = await r.json()
            return data.get("guild", {}).get("name")
    except:
        return None

# বট ইভেন্টস
@bot.event
async def on_ready():
    global http_session
    http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
    logger.info(f"✅ Logged in as {bot.user}")
    logger.info(f"📊 Loaded {len(compiled_scam_patterns)} scam patterns")
    logger.info(f"🔍 Hash database: {len(scam_hash_database.get('hashes', []))} known scam images")
    logger.info(f"⚙️ Security Level: Advanced")
    
    try:
        synced = await bot.tree.sync()
        logger.info(f"📡 Synced {len(synced)} commands")
    except Exception as e:
        logger.error(f"❌ Failed to sync commands: {e}")

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    
    # Spam Detection
    user_id = message.author.id
    now = datetime.now(timezone.utc).timestamp()
    
    if user_id not in spam_control:
        spam_control[user_id] = []
    
    spam_control[user_id].append(now)
    
    # Clean up old timestamps
    spam_control[user_id] = [t for t in spam_control[user_id] if now - t < config.get("spam_interval", 10)]
    
    if len(spam_control[user_id]) > config.get("spam_threshold", 5):
        await handle_violation(message, "Spam detected (Too many messages)", SecurityLevel.MEDIUM)
        spam_control[user_id] = [] # Reset after action
        return

    # ইগনোর রোল চেক
    if any(r.id in config["ignored_roles"] for r in getattr(message.author, "roles", [])):
        await bot.process_commands(message)
        return
    
    # Bad Word Filter
    content_lower = message.content.lower()
    for word in config.get("bad_words", []):
        if word.lower() in content_lower:
            await handle_violation(message, f"Bad word detected: {word}", SecurityLevel.LOW)
            return
    
    # ইনভাইট লিংক চেক
    for code in INVITE_RE.findall(message.content):
        name = await resolve_invite_name(code)
        if name and any(blocked.lower() in name.lower() for blocked in config["blocked_server_names"]):
            await handle_violation(message, f"Blocked server invite: {name}", SecurityLevel.HIGH)
            return
    
    # URL চেক
    if message.content:
        urls = URL_RE.findall(message.content)
        for url in urls:
            if check_phishing_url(url):
                await handle_violation(message, f"Phishing URL detected: {url}", SecurityLevel.CRITICAL)
                return
    
    # ইমেজ স্ক্যান
    if message.attachments:
        for att in message.attachments:
            if not (att.content_type or "").startswith("image/"):
                continue
            if att.filename.lower().endswith(".gif"):
                continue
            if att.size > MAX_IMAGE_SIZE:
                continue
            
            try:
                image_bytes = await fetch_bytes(att.url)
                text = await run_ocr(image_bytes)
                
                threats, level = await advanced_scam_check(message, text, image_bytes)
                
                if threats:
                    reason = " | ".join(threats)
                    await handle_violation(message, reason, level)
                    return
            except Exception as e:
                logger.error(f"Image scan failed: {e}")
    
    await bot.process_commands(message)

# Advanced Logging & Events
@bot.event
async def on_member_join(member):
    # Auto Role
    role_id = config.get("auto_role_id")
    if role_id:
        role = member.guild.get_role(int(role_id))
        if role:
            try:
                await member.add_roles(role)
                logger.info(f"Assigned auto-role to {member}")
            except Exception as e:
                logger.error(f"Failed to assign auto-role: {e}")

    # Welcome Message
    welcome_ch_id = config.get("welcome_channel_id")
    if welcome_ch_id:
        channel = bot.get_channel(int(welcome_ch_id))
        if channel:
            embed = discord.Embed(
                title="👋 Welcome to the server!",
                description=f"Hello {member.mention}, welcome to **{member.guild.name}**! We are glad to have you here.",
                color=discord.Color.green()
            )
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.add_field(name="Account Created", value=member.created_at.strftime("%Y-%m-%d"), inline=True)
            embed.set_footer(text=f"Member #{len(member.guild.members)}")
            await channel.send(embed=embed)

@bot.event
async def on_member_remove(member):
    welcome_ch_id = config.get("welcome_channel_id")
    if welcome_ch_id:
        channel = bot.get_channel(int(welcome_ch_id))
        if channel:
            embed = discord.Embed(
                title="😢 Goodbye!",
                description=f"{member.display_name} has left the server. We'll miss you!",
                color=discord.Color.red()
            )
            await channel.send(embed=embed)

@bot.event
async def on_message_edit(before, after):
    if before.author.bot or before.content == after.content:
        return
    
    log_id = config.get("log_channel_id")
    if log_id:
        log_ch = bot.get_channel(int(log_id))
        if log_ch:
            embed = discord.Embed(title="📝 Message Edited", color=discord.Color.blue())
            embed.add_field(name="User", value=before.author.mention, inline=True)
            embed.add_field(name="Channel", value=before.channel.mention, inline=True)
            embed.add_field(name="Before", value=before.content[:1024] or "None", inline=False)
            embed.add_field(name="After", value=after.content[:1024] or "None", inline=False)
            await log_ch.send(embed=embed)

@bot.event
async def on_message_delete(message):
    if message.author.bot:
        return
    
    log_id = config.get("log_channel_id")
    if log_id:
        log_ch = bot.get_channel(int(log_id))
        if log_ch:
            embed = discord.Embed(title="🗑️ Message Deleted", color=discord.Color.red())
            embed.add_field(name="User", value=message.author.mention, inline=True)
            embed.add_field(name="Channel", value=message.channel.mention, inline=True)
            embed.add_field(name="Content", value=message.content[:1024] or "None", inline=False)
            await log_ch.send(embed=embed)

# অ্যাডমিন কমান্ড গ্রুপ
def admin_only():
    async def check(i):
        return i.user.guild_permissions.administrator
    return app_commands.check(check)

g = app_commands.Group(name="scam", description="Advanced Scam Protection System")

# /fullscan - পুরো চ্যানেল স্ক্যান
@g.command(name="fullscan", description="Complete channel scan for scam content")
@admin_only()
async def fullscan(
    interaction: discord.Interaction, 
    channel: Optional[discord.TextChannel] = None,
    limit: Optional[int] = 1000,
    delete_scams: Optional[bool] = True
):
    await interaction.response.defer(ephemeral=True)
    
    channels = [channel] if channel else [
        ch for ch in interaction.guild.text_channels 
        if ch.permissions_for(interaction.guild.me).read_message_history
    ]
    
    total_scanned = 0
    total_found = 0
    total_users = set()
    
    for ch in channels:
        await interaction.edit_original_response(
            content=f"🔍 Scanning #{ch.name}... ({total_found} violations found so far)"
        )
        
        scanned, found, users = await full_scan_channel(
            ch, 
            limit=limit, 
            delete_scams=delete_scams,
            scan_embeds=True
        )
        
        total_scanned += scanned
        total_found += found
        total_users.update([users])
    
    # ফাইনাল রিপোর্ট
    embed = discord.Embed(
        title="✅ Full Scan Complete",
        color=discord.Color.green() if total_found == 0 else discord.Color.red()
    )
    embed.add_field(name="Channels Scanned", value=str(len(channels)), inline=True)
    embed.add_field(name="Messages Scanned", value=str(total_scanned), inline=True)
    embed.add_field(name="Violations Found", value=str(total_found), inline=True)
    embed.add_field(name="Unique Users Flagged", value=str(len(total_users)), inline=True)
    embed.add_field(name="Scam Images Deleted", value=str(total_found) if delete_scams else "0 (disabled)", inline=True)
    
    await interaction.edit_original_response(content=None, embed=embed)

# /scan - দ্রুত স্ক্যান
@g.command(name="scan", description="Quick scan of recent messages")
@admin_only()
async def scan(interaction: discord.Interaction, channel: discord.TextChannel | None = None, limit: int = 100):
    await interaction.response.defer(ephemeral=True)
    
    channels = [channel] if channel else [
        ch for ch in interaction.guild.text_channels 
        if ch.permissions_for(interaction.guild.me).read_message_history
    ]
    
    found = 0
    scanned = 0
    
    for ch in channels:
        await interaction.edit_original_response(
            content=f"Quick scanning #{ch.name}... ({found} found)"
        )
        
        try:
            async for msg in ch.history(limit=limit):
                if msg.author.bot or not msg.attachments:
                    continue
                
                for att in msg.attachments:
                    if not (att.content_type or "").startswith("image/"):
                        continue
                    if att.size > MAX_IMAGE_SIZE:
                        continue
                    
                    try:
                        image_bytes = await fetch_bytes(att.url)
                        text = await run_ocr(image_bytes)
                        match = scam_match(text)
                        if match:
                            found += 1
                            await handle_violation(msg, f"Scam pattern [scan]: {match}")
                        scanned += 1
                    except:
                        continue
        except discord.Forbidden:
            continue
    
    await interaction.edit_original_response(
        content=f"✅ Quick scan complete!\n📊 Scanned: {scanned} images\n🚫 Found: {found} violations"
    )

# /security - সিকিউরিটি স্ট্যাটাস
@g.command(name="security", description="View security status and statistics")
@admin_only()
async def security_status(interaction):
    embed = discord.Embed(
        title="🛡️ Security System Status",
        color=discord.Color.blue()
    )
    
    embed.add_field(name="Scam Patterns", value=str(len(compiled_scam_patterns)), inline=True)
    embed.add_field(name="Known Scam Hashes", value=str(len(scam_hash_database.get("hashes", []))), inline=True)
    embed.add_field(name="Blocked Servers", value=str(len(config["blocked_server_names"])), inline=True)
    embed.add_field(name="Total Warnings", value=str(len(user_warnings)), inline=True)
    embed.add_field(name="Auto-Delete", value="ON" if config["delete_messages"] else "OFF", inline=True)
    embed.add_field(name="Max Warnings", value=str(config.get("max_warnings_before_mute", 5)), inline=True)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# /addhash - স্ক্যাম ইমেজ হ্যাশ অ্যাড
@g.command(name="addhash", description="Add image hash to scam database")
@admin_only()
async def add_hash(interaction, message_id: str):
    try:
        msg = await interaction.channel.fetch_message(int(message_id))
        
        if not msg.attachments:
            await interaction.response.send_message("No image found in that message!", ephemeral=True)
            return
        
        for att in msg.attachments:
            if att.content_type.startswith("image/"):
                image_bytes = await fetch_bytes(att.url)
                img_hash = get_image_hash(image_bytes)
                
                if img_hash:
                    if img_hash not in scam_hash_database.get("hashes", []):
                        scam_hash_database["hashes"].append(img_hash)
                        save_json_file(HASH_DB_FILE, scam_hash_database)
                        await interaction.response.send_message(f"✅ Added hash: {img_hash}", ephemeral=True)
                    else:
                        await interaction.response.send_message("Hash already exists!", ephemeral=True)
                return
        
        await interaction.response.send_message("Could not process image!", ephemeral=True)
    except:
        await interaction.response.send_message("Invalid message ID!", ephemeral=True)

# /warnings - ইউজার ওয়ার্নিং দেখুন
@g.command(name="warnings", description="Check user warnings")
@admin_only()
async def check_warnings(interaction, user: discord.User):
    user_id = str(user.id)
    
    if user_id not in user_warnings:
        await interaction.response.send_message(f"No warnings for {user.mention}", ephemeral=True)
        return
    
    warnings_data = user_warnings[user_id]
    
    embed = discord.Embed(
        title=f"⚠️ Warnings for {user}",
        color=discord.Color.orange()
    )
    embed.add_field(name="Total Warnings", value=str(warnings_data["count"]), inline=False)
    
    recent_warnings = warnings_data["warnings"][-5:]  # লাস্ট 5
    for i, warning in enumerate(recent_warnings, 1):
        embed.add_field(
            name=f"Warning #{i}",
            value=f"**Reason:** {warning['reason']}\n**Date:** {warning['timestamp'][:10]}",
            inline=False
        )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# /clearwarnings - ওয়ার্নিং ক্লিয়ার
@g.command(name="clearwarnings", description="Clear user warnings")
@admin_only()
async def clear_warnings(interaction, user: discord.User):
    user_id = str(user.id)
    
    if user_id in user_warnings:
        del user_warnings[user_id]
        save_json_file(USER_WARNINGS_FILE, user_warnings)
        await interaction.response.send_message(f"✅ Cleared all warnings for {user.mention}", ephemeral=True)
    else:
        await interaction.response.send_message("No warnings found!", ephemeral=True)

# এক্সিস্টিং কমান্ডগুলো
@g.command(name="config", description="View current settings")
@admin_only()
async def show_config(interaction):
    log = f"<#{config['log_channel_id']}>" if config["log_channel_id"] else "None"
    keywords = "\n".join(f"`{i}` {k}" for i, k in enumerate(config["scam_keywords"]))
    servers = ", ".join(config["blocked_server_names"]) or "none"
    
    await interaction.response.send_message(
        f"**Security Settings:**\n"
        f"Delete: {config['delete_messages']} | Log: {log}\n"
        f"Max Warnings: {config.get('max_warnings_before_mute', 5)}\n"
        f"Blocked servers: {servers}\n\n"
        f"**Scam Keywords:**\n{keywords}",
        ephemeral=True,
    )

@g.command(name="set", description="Configure bot settings")
@admin_only()
async def set_setting(interaction, setting: str, value: str):
    if setting == "delete":
        config["delete_messages"] = value.lower() == "true"
        save_config(config)
        await interaction.response.send_message(f"Auto-delete: {config['delete_messages']}", ephemeral=True)
    
    elif setting == "log":
        config["log_channel_id"] = None if value.lower() == "clear" else int(re.sub(r"\D", "", value))
        save_config(config)
        log = f"<#{config['log_channel_id']}>" if config["log_channel_id"] else "cleared"
        await interaction.response.send_message(f"Log channel: {log}", ephemeral=True)
    
    elif setting == "maxwarnings":
        config["max_warnings_before_mute"] = int(value)
        save_config(config)
        await interaction.response.send_message(f"Max warnings: {config['max_warnings_before_mute']}", ephemeral=True)
    
    else:
        await interaction.response.send_message("Options: delete, log, maxwarnings", ephemeral=True)

@g.command(name="keyword", description="Add/remove scam keywords")
@admin_only()
async def keyword(interaction, action: str, value: str):
    global compiled_scam_patterns
    keywords = config["scam_keywords"]
    
    if action == "add":
        keywords.append(value)
        compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in keywords]
        save_config(config)
        await interaction.response.send_message(f"✅ Added keyword: `{value}`", ephemeral=True)
    
    elif action == "remove":
        idx = int(value)
        if 0 <= idx < len(keywords):
            removed = keywords.pop(idx)
            compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in keywords]
            save_config(config)
            await interaction.response.send_message(f"❌ Removed keyword: `{removed}`", ephemeral=True)
        else:
            await interaction.response.send_message("Invalid index!", ephemeral=True)
    
    else:
        await interaction.response.send_message("Use: add <pattern> or remove <index>", ephemeral=True)

@g.command(name="badword", description="Add/remove bad words from filter")
@admin_only()
async def badword(interaction: discord.Interaction, action: str, word: str):
    words = config.get("bad_words", [])
    if action == "add":
        if word.lower() not in [w.lower() for w in words]:
            words.append(word)
            save_config(config)
            await interaction.response.send_message(f"✅ Added bad word: `{word}`", ephemeral=True)
        else:
            await interaction.response.send_message("Word already exists!", ephemeral=True)
    elif action == "remove":
        if word in words:
            words.remove(word)
            save_config(config)
            await interaction.response.send_message(f"❌ Removed bad word: `{word}`", ephemeral=True)
        else:
            await interaction.response.send_message("Word not found!", ephemeral=True)
    else:
        await interaction.response.send_message("Use: add/remove", ephemeral=True)

@g.command(name="server", description="Manage blocked servers")
@admin_only()
async def server(interaction, action: str, name: str):
    lst = config["blocked_server_names"]
    name_l = name.lower()
    
    if action == "add":
        if name_l not in lst:
            lst.append(name_l)
        save_config(config)
        await interaction.response.send_message(f"🚫 Blocked: {name}", ephemeral=True)
    
    elif action == "remove":
        if name_l in lst:
            lst.remove(name_l)
            save_config(config)
            await interaction.response.send_message(f"✅ Unblocked: {name}", ephemeral=True)
        else:
            await interaction.response.send_message("Not found!", ephemeral=True)
    
    else:
        await interaction.response.send_message("Use: add/remove", ephemeral=True)

@g.command(name="setlog", description="Set the channel for security and activity logs")
@admin_only()
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    config["log_channel_id"] = channel.id
    save_config(config)
    
    embed = discord.Embed(
        title="✅ Log Channel Updated",
        description=f"All security alerts and activity logs will now be sent to {channel.mention}",
        color=discord.Color.green()
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)
    
    # Send a test message to the new log channel
    test_embed = discord.Embed(
        title="🔒 Logging System Active",
        description="This channel has been successfully set as the primary log channel for Sentinax.",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    await channel.send(embed=test_embed)

@g.command(name="setwelcome", description="Set the channel for welcome and leave messages")
@admin_only()
async def set_welcome_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    config["welcome_channel_id"] = channel.id
    save_config(config)
    
    embed = discord.Embed(
        title="✅ Welcome Channel Updated",
        description=f"Welcome and leave messages will now be sent to {channel.mention}",
        color=discord.Color.green()
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)

@g.command(name="ignorerole", description="Toggle role bypass")
@admin_only()
async def ignore_role(interaction, role: discord.Role):
    lst = config["ignored_roles"]
    
    if role.id in lst:
        lst.remove(role.id)
        verb = "removed from ignore list"
    else:
        lst.append(role.id)
        verb = "added to ignore list"
    
    save_config(config)
    await interaction.response.send_message(f"{role.mention} {verb}", ephemeral=True)

# সিকিউরিটি অডিট
@g.command(name="audit", description="Security audit for recent members")
@admin_only()
async def security_audit(interaction, days: int = 7):
    await interaction.response.defer(ephemeral=True)
    
    suspicious_users = []
    
    for member in interaction.guild.members:
        if check_account_age(member, days) and not member.bot:
            warnings_count = 0
            if str(member.id) in user_warnings:
                warnings_count = user_warnings[str(member.id)]["count"]
            
            suspicious_users.append({
                "user": member,
                "age": (datetime.now(timezone.utc) - member.created_at).days,
                "warnings": warnings_count
            })
    
    if suspicious_users:
        embed = discord.Embed(
            title=f"🔍 Security Audit - New Accounts ({len(suspicious_users)} found)",
            description=f"Accounts created in the last {days} days:",
            color=discord.Color.yellow()
        )
        
        for data in suspicious_users[:10]:  # টপ 10
            user = data["user"]
            embed.add_field(
                name=f"{user} ({data['age']} days old)",
                value=f"Warnings: {data['warnings']} | ID: {user.id}",
                inline=False
            )
        
        if len(suspicious_users) > 10:
            embed.set_footer(text=f"And {len(suspicious_users) - 10} more...")
        
        await interaction.edit_original_response(embed=embed)
    else:
        await interaction.edit_original_response(content="✅ No suspicious new accounts found!")

# স্ক্যাম ম্যাচ ফাংশন
def scam_match(text):
    for pattern in compiled_scam_patterns:
        if pattern.search(text):
            return pattern.pattern
    return None

bot.tree.add_command(g)

# Moderation Commands
m = app_commands.Group(name="mod", description="Advanced Moderation System")

@m.command(name="kick", description="Kick a member from the server")
@admin_only()
async def kick(interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = "No reason provided"):
    try:
        await member.kick(reason=reason)
        embed = discord.Embed(title="👢 Member Kicked", color=discord.Color.orange())
        embed.add_field(name="User", value=f"{member} ({member.id})")
        embed.add_field(name="Reason", value=reason)
        embed.set_footer(text=f"By {interaction.user}")
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed to kick: {e}", ephemeral=True)

@m.command(name="ban", description="Ban a member from the server")
@admin_only()
async def ban(interaction: discord.Interaction, member: discord.Member, reason: Optional[str] = "No reason provided", delete_days: int = 0):
    try:
        await member.ban(reason=reason, delete_message_days=delete_days)
        embed = discord.Embed(title="🚫 Member Banned", color=discord.Color.red())
        embed.add_field(name="User", value=f"{member} ({member.id})")
        embed.add_field(name="Reason", value=reason)
        embed.set_footer(text=f"By {interaction.user}")
        await interaction.response.send_message(embed=embed)
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed to ban: {e}", ephemeral=True)

@m.command(name="unban", description="Unban a member by ID")
@admin_only()
async def unban(interaction: discord.Interaction, user_id: str):
    try:
        user = await bot.fetch_user(int(user_id))
        await interaction.guild.unban(user)
        await interaction.response.send_message(f"✅ Unbanned {user} ({user_id})")
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed to unban: {e}", ephemeral=True)

@m.command(name="clear", description="Clear messages in a channel")
@admin_only()
async def clear(interaction: discord.Interaction, amount: int):
    if amount < 1:
        await interaction.response.send_message("Please provide a number greater than 0", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=amount)
    await interaction.edit_original_response(content=f"✅ Deleted {len(deleted)} messages")

@m.command(name="mute", description="Timeout a member")
@admin_only()
async def mute(interaction: discord.Interaction, member: discord.Member, minutes: int, reason: Optional[str] = "No reason provided"):
    try:
        duration = timedelta(minutes=minutes)
        await member.timeout(duration, reason=reason)
        await interaction.response.send_message(f"🔇 {member.mention} has been muted for {minutes} minutes. Reason: {reason}")
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed to mute: {e}", ephemeral=True)

@m.command(name="unmute", description="Remove timeout from a member")
@admin_only()
async def unmute(interaction: discord.Interaction, member: discord.Member):
    try:
        await member.timeout(None)
        await interaction.response.send_message(f"🔊 Removed timeout for {member.mention}")
    except Exception as e:
        await interaction.response.send_message(f"❌ Failed to unmute: {e}", ephemeral=True)

bot.tree.add_command(m)

# Crypto Commands
c = app_commands.Group(name="crypto", description="Cryptocurrency information and tracking")

@c.command(name="price", description="Get current price of a cryptocurrency")
async def crypto_price(interaction: discord.Interaction, coin: str = "bitcoin"):
    await interaction.response.defer()
    try:
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin.lower()}&vs_currencies=usd&include_24hr_change=true"
        async with http_session.get(url) as r:
            if r.status == 200:
                data = await r.json()
                if coin.lower() in data:
                    price = data[coin.lower()]["usd"]
                    change = data[coin.lower()]["usd_24h_change"]
                    
                    embed = discord.Embed(
                        title=f"💰 {coin.capitalize()} Price",
                        color=discord.Color.green() if change > 0 else discord.Color.red()
                    )
                    embed.add_field(name="Price", value=f"${price:,.2f} USD")
                    embed.add_field(name="24h Change", value=f"{change:.2f}%")
                    embed.set_footer(text="Data from CoinGecko")
                    await interaction.followup.send(embed=embed)
                else:
                    await interaction.followup.send(f"❌ Could not find coin: `{coin}`. Please use the full name (e.g., bitcoin, ethereum).")
            else:
                await interaction.followup.send("❌ Failed to fetch price from API.")
    except Exception as e:
        await interaction.followup.send(f"❌ Error: {e}")

bot.tree.add_command(c)

# Utility Commands
u = app_commands.Group(name="utility", description="Useful utility commands")

@u.command(name="serverinfo", description="View server information")
async def server_info(interaction: discord.Interaction):
    guild = interaction.guild
    embed = discord.Embed(title=f"📊 Server Info: {guild.name}", color=discord.Color.blue())
    embed.set_thumbnail(url=guild.icon.url if guild.icon else None)
    embed.add_field(name="Owner", value=guild.owner.mention, inline=True)
    embed.add_field(name="Created At", value=guild.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Total Members", value=str(guild.member_count), inline=True)
    embed.add_field(name="Roles", value=str(len(guild.roles)), inline=True)
    embed.add_field(name="Channels", value=str(len(guild.channels)), inline=True)
    embed.set_footer(text=f"ID: {guild.id}")
    await interaction.response.send_message(embed=embed)

@u.command(name="userinfo", description="View user information")
async def user_info(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    member = member or interaction.user
    embed = discord.Embed(title=f"👤 User Info: {member}", color=member.color)
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="ID", value=str(member.id), inline=True)
    embed.add_field(name="Joined Server", value=member.joined_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Joined Discord", value=member.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Top Role", value=member.top_role.mention, inline=True)
    await interaction.response.send_message(embed=embed)

bot.tree.add_command(u)

# Help Command
@bot.tree.command(name="help", description="Show all available commands and how to use the bot")
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ Advanced Security Bot Help",
        description="Welcome! Here is the list of available commands grouped by category. All moderation and security commands require **Administrator** permissions.",
        color=discord.Color.blue()
    )
    
    # Scam Protection Group
    scam_cmds = (
        "`/scam fullscan` - Scan channel for scams\n"
        "`/scam security` - View security stats\n"
        "`/scam config` - View current settings\n"
        "`/scam setlog` - Set logging channel\n"
        "`/scam setwelcome` - Set welcome channel\n"
        "`/scam keyword` - Manage scam keywords\n"
        "`/scam badword` - Manage bad word filter\n"
        "`/scam warnings` - Check user warnings"
    )
    embed.add_field(name="🛡️ Scam Protection (/scam)", value=scam_cmds, inline=False)
    
    # Moderation Group
    mod_cmds = (
        "`/mod clear` - Delete messages\n"
        "`/mod kick` - Kick a member\n"
        "`/mod ban` - Ban a member\n"
        "`/mod mute` - Timeout a member\n"
        "`/mod unmute` - Remove timeout"
    )
    embed.add_field(name="🔨 Moderation (/mod)", value=mod_cmds, inline=False)
    
    # Utility Group
    util_cmds = (
        "`/utility serverinfo` - View server stats\n"
        "`/utility userinfo` - View user details"
    )
    embed.add_field(name="⚙️ Utility (/utility)", value=util_cmds, inline=False)
    
    # Crypto Group
    crypto_cmds = (
        "`/crypto price` - Get live crypto prices"
    )
    embed.add_field(name="💰 Crypto (/crypto)", value=crypto_cmds, inline=False)
    
    embed.set_footer(text="Tip: Type / and select a command to see more details about its parameters.")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.command(name="help")
async def prefix_help(ctx):
    embed = discord.Embed(
        title="🛡️ Advanced Security Bot Help",
        description="Use slash commands for better experience! Type `/` to see all commands.",
        color=discord.Color.blue()
    )
    embed.add_field(name="Available Groups", value="`/scam`, `/mod`, `/crypto`", inline=False)
    embed.add_field(name="Help Command", value="Type `/help` for detailed information.", inline=False)
    await ctx.send(embed=embed)

# বট রান
if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        logger.error("❌ No token found! Please set DISCORD_TOKEN in .env file")
    else:
        logger.info("🚀 Starting Advanced Security Bot...")
        bot.run(token)