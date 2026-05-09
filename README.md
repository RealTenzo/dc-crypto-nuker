# dc crypto nuker

A Discord bot that detects scam images and spam invites. The ScamShield bot can read text from images using Optical Character Recognition (OCR).

## Installation Instructions

```sh
pip install discord.py aiohttp easyocr numpy pillow python-dotenv
```

Create a `.env` file with the contents:

```
DISCORD_TOKEN=your_token_here
```
Run the bot from the terminal by typing:

```sh
py bot.py
```

## Commands

Commands are under the `/scam` group, for admin use only:

- `/scam config` - View the bot's current settings
- `/scam scan` - Perform scans on previously written messages
- `/scam set` - Toggle between whether or not to delete/log messages
- `/scam keyword add/remove` - Add/remove keywords used to identify scams
- `/scam server add/remove` - Add/remove servers you want ScamShield to monitor
- `/scam ignorerole` - Bypasses defined roles

## How It Works

1. Monitors messages for incoming messages.
2. Monitors all incoming messages for unwanted invite links.
3. Uses OCR software to read all the images that are sent directly into Discord.
4. If the OCR detects a scam related word/concept it will delete the message and notify the sender via DM and log it to the channel. 

The bot stores all its configuration settings in a config.json file that can be edited or you can use the bot commands to update.
