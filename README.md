# Sentinax - Advanced Security & Moderation Bot

Sentinax is a powerful, all-in-one Discord bot designed to protect your server from scams, spam, and bad actors while providing professional moderation and utility tools. It features advanced OCR (Optical Character Recognition) to detect scam text within images.

## ✨ Features

- **🛡️ Scam Protection:** Uses OCR to read text from images and detect scam patterns.
- **🚫 Phishing Detection:** Automatically blocks known phishing URLs and suspicious invites.
- **🔨 Advanced Moderation:** Slash commands for Kick, Ban, Mute (Timeout), and Message Clearing.
- **🛑 Spam Prevention:** Auto-detects and handles rapid message spamming.
- **🤬 Bad Word Filter:** Customizable filter to keep your chat clean.
- **💰 Crypto Tracker:** Live cryptocurrency price updates from CoinGecko.
- **📝 Advanced Logging:** Logs message edits, deletions, and security violations.
- **👋 Welcome & Auto-Role:** Welcomes new members and assigns roles automatically.
- **⚙️ Utility Tools:** Quick access to server and user information.

## 🚀 Installation Instructions

1. **Install Dependencies:**
   ```sh
   pip install -r Requirements.txt
   ```

2. **Setup Environment:**
   Create a `.env` file in the root directory:
   ```env
   DISCORD_TOKEN=your_discord_bot_token_here
   ```

3. **Run the Bot:**
   ```sh
   python bot.py
   ```

## 📜 Commands

Sentinax uses **Slash Commands** for a better user experience.

### 🛡️ Scam & Security (`/scam`)
- `/scam fullscan` - Complete channel scan for scam content.
- `/scam security` - View security status and statistics.
- `/scam config` - View current security settings.
- `/scam set` - Configure bot settings (delete, log, maxwarnings).
- `/scam keyword` - Add/remove scam detection keywords.
- `/scam badword` - Manage the bad word filter list.
- `/scam warnings` - Check a user's warning history.

### 🔨 Moderation (`/mod`)
- `/mod clear` - Bulk delete messages from a channel.
- `/mod kick` - Kick a member from the server.
- `/mod ban` - Ban a member from the server.
- `/mod mute` - Timeout a member for a specified duration.
- `/mod unmute` - Remove timeout from a member.

### 💰 Crypto (`/crypto`)
- `/crypto price` - Get live price and 24h change of any coin (e.g., bitcoin).

### ⚙️ Utility (`/utility`)
- `/utility serverinfo` - Display detailed server statistics.
- `/utility userinfo` - Show information about a specific member.

### ❓ Help (`/help`)
- `/help` - Show all available commands and guides.

## 🛠️ Configuration

The bot stores settings in `config.json`. You can also configure:
- `welcome_channel_id`: ID for join/leave messages.
- `log_channel_id`: ID for security and edit/delete logs.
- `auto_role_id`: Role ID assigned to new members automatically.

## 🛡️ How It Works

1. **OCR Scanning:** When an image is sent, Sentinax uses `easyocr` to extract text and checks it against known scam patterns.
2. **Real-time Monitoring:** Every message is analyzed for phishing links, blacklisted invites, and spam behavior.
3. **Automated Actions:** Based on the security level, the bot can warn, mute, or ban users automatically to keep the server safe.

---
*Built with ❤️ for a safer Discord community.*
