import discord
from discord.ext import commands
from discord import app_commands

import aiohttp
import easyocr
import numpy as np
from PIL import Image
import io
import re
import json
import asyncio
import warnings
import hashlib
import os
from pathlib import Path
from functools import partial
from dotenv import load_dotenv
from collections import OrderedDict

warnings.filterwarnings("ignore")
load_dotenv()

# config stuff
CONFIG_FILE = Path("config.json")
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
}

MAX_IMAGE_SIZE = 8 * 1024 * 1024
OCR_MAX_DIMENSION = 900
OCR_CONCURRENCY = 2
OCR_CACHE_LIMIT = 1000

INVITE_RE = re.compile(r"discord(?:\.gg|app\.com/invite)/([a-zA-Z0-9\-]+)")
SUSPICIOUS_TEXT = ("$", "crypto", "usdt", "btc", "withdraw", "claim", "cashout", "casino")

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

config = load_config()
compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in config["scam_keywords"]]

# ocr model
print("Loading OCR model...")
ocr = easyocr.Reader(["en"], gpu=False, verbose=False, detector=True, recognizer=True)
print("OCR Ready.")

ocr_semaphore = asyncio.Semaphore(OCR_CONCURRENCY)
ocr_cache = OrderedDict()

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)
http_session = None

# actual ocr work
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

# quick check
def scam_match(text):
    for pattern in compiled_scam_patterns:
        if pattern.search(text):
            return pattern.pattern
    return None

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

# handles violation stuff
async def handle_violation(message, reason):
    deleted = False

    if config["delete_messages"]:
        try:
            await message.delete()
            deleted = True
        except:
            pass

    try:
        await message.author.send(
            f"Your message in **{message.guild.name} / #{message.channel.name}** "
            f"was {'deleted' if deleted else 'flagged'}.\n\n"
            f"Reason: We have detected an scam image! | There is an chance your account has been grabbed please check!"
            f"Contact a moderator if you think this is a mistake."
        )
    except:
        pass

    log_id = config.get("log_channel_id")
    if log_id:
        log_ch = bot.get_channel(int(log_id))
        if log_ch:
            embed = discord.Embed(title="Scam Detected", color=discord.Color.red())
            embed.add_field(name="User", value=f"{message.author.mention} (`{message.author.id}`)", inline=False)
            embed.add_field(name="Channel", value=message.channel.mention, inline=False)
            embed.add_field(name="Reason", value=f"`{reason}`", inline=False)
            embed.add_field(name="Deleted", value="Yes" if deleted else "No", inline=False)
            embed.set_footer(text=f"Message ID: {message.id}")
            await log_ch.send(embed=embed)

async def sync_commands():
    for attempt in range(5):
        try:
            await bot.tree.sync()
            return
        except discord.errors.DiscordServerError:
            wait = 15 * (attempt + 1)
            print(f"Sync failed (503), retrying in {wait}s...")
            await asyncio.sleep(wait)
    print("Could not sync commands after 5 attempts.")

# events
@bot.event
async def on_ready():
    global http_session
    http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
    print(f"Logged in as {bot.user}")
    asyncio.create_task(sync_commands())

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    if any(r.id in config["ignored_roles"] for r in getattr(message.author, "roles", [])):
        return

    # invite link check
    for code in INVITE_RE.findall(message.content):
        name = await resolve_invite_name(code)
        if name and any(blocked.lower() in name.lower() for blocked in config["blocked_server_names"]):
            await handle_violation(message, f"invite to blocked server: {name}")
            return

    lowered_content = message.content.lower()
    should_scan = any(x in lowered_content for x in SUSPICIOUS_TEXT)

    if not message.attachments:
        await bot.process_commands(message)
        return

    # image scanning
    for att in message.attachments:
        if not (att.content_type or "").startswith("image/"):
            continue
        if att.filename.lower().endswith(".gif"):
            continue
        if att.size > MAX_IMAGE_SIZE:
            continue

        try:
            print(f"Scanning {att.filename} from {message.author}")
            image_bytes = await fetch_bytes(att.url)
            text = await run_ocr(image_bytes)
            print(f"Found uh proof very real in image")

            match = scam_match(text)
            if match:
                await handle_violation(message, f"scam pattern: {match}")
                return
        except Exception as e:
            print(f"Attachment scan failed: {e}")

    await bot.process_commands(message)

@bot.event
async def on_close():
    if http_session:
        await http_session.close()

# admin only
def admin_only():
    async def check(i):
        return i.user.guild_permissions.administrator
    return app_commands.check(check)

g = app_commands.Group(name="scam", description="Scam bot config")

# scan history
@g.command(name="scan", description="Scan last 1000 messages for scam images")
@admin_only()
async def scan(interaction: discord.Interaction, channel: discord.TextChannel | None = None):
    await interaction.response.defer(ephemeral=True)

    channels = (
        [channel]
        if channel
        else [ch for ch in interaction.guild.text_channels if ch.permissions_for(interaction.guild.me).read_message_history]
    )

    found = 0
    scanned = 0

    for ch in channels:
        await interaction.edit_original_response(content=f"Scanning #{ch.name}... ({found} found)")

        try:
            async for msg in ch.history(limit=1000):
                if msg.author.bot:
                    continue
                if not msg.attachments:
                    continue

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
                        match = scam_match(text)
                        if match:
                            found += 1
                            await handle_violation(msg, f"scam pattern [scan]: {match}")
                        scanned += 1
                    except Exception as e:
                        print(f"Scan failed: {e}")
        except discord.Forbidden:
            continue

    await interaction.edit_original_response(
        content=f"Done.\nScanned {scanned} image(s)\nRemoved {found} scam(s)"
    )

# view config
@g.command(name="config", description="View current settings")
@admin_only()
async def show_config(interaction):
    log = f"<#{config['log_channel_id']}>" if config["log_channel_id"] else "None"
    keywords = "\n".join(f"`{i}` {k}" for i, k in enumerate(config["scam_keywords"]))
    servers = ", ".join(config["blocked_server_names"]) or "none"

    await interaction.response.send_message(
        f"Delete: {config['delete_messages']} | Log: {log}\n"
        f"Blocked servers: {servers}\n\n"
        f"Keywords:\n{keywords}",
        ephemeral=True,
    )

# settings
@g.command(name="set", description="delete true/false | log #channel or clear")
@admin_only()
async def set_setting(interaction, setting: str, value: str):
    global compiled_scam_patterns

    if setting == "delete":
        config["delete_messages"] = value.lower() == "true"
        save_config(config)
        await interaction.response.send_message(f"Delete: {config['delete_messages']}", ephemeral=True)

    elif setting == "log":
        config["log_channel_id"] = None if value.lower() == "clear" else int(re.sub(r"\D", "", value))
        save_config(config)
        log = f"<#{config['log_channel_id']}>" if config["log_channel_id"] else "cleared"
        await interaction.response.send_message(f"Log: {log}", ephemeral=True)

    else:
        await interaction.response.send_message("Options: delete, log", ephemeral=True)

# keyword management
@g.command(name="keyword", description="add <pattern> | remove <index>")
@admin_only()
async def keyword(interaction, action: str, value: str):
    global compiled_scam_patterns
    keywords = config["scam_keywords"]

    if action == "add":
        keywords.append(value)
        compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in keywords]
        save_config(config)
        await interaction.response.send_message(f"Added: `{value}`", ephemeral=True)

    elif action == "remove":
        idx = int(value)
        if not 0 <= idx < len(keywords):
            await interaction.response.send_message("Invalid index", ephemeral=True)
            return
        removed = keywords.pop(idx)
        compiled_scam_patterns = [re.compile(p, re.IGNORECASE) for p in keywords]
        save_config(config)
        await interaction.response.send_message(f"Removed: `{removed}`", ephemeral=True)

    else:
        await interaction.response.send_message("Use: add <pattern> or remove <index>", ephemeral=True)

# blocked servers
@g.command(name="server", description="add/remove blocked server name")
@admin_only()
async def server(interaction, action: str, name: str):
    lst = config["blocked_server_names"]
    name_l = name.lower()

    if action == "add":
        if name_l not in lst:
            lst.append(name_l)
        save_config(config)
        await interaction.response.send_message(f"Blocked: {name}", ephemeral=True)

    elif action == "remove":
        if name_l not in lst:
            await interaction.response.send_message("Not found", ephemeral=True)
            return
        lst.remove(name_l)
        save_config(config)
        await interaction.response.send_message(f"Unblocked: {name}", ephemeral=True)

    else:
        await interaction.response.send_message("Use: add/remove", ephemeral=True)

@g.command(name="ignorerole", description="Toggle role bypass")
@admin_only()
async def ignore_role(interaction, role: discord.Role):
    lst = config["ignored_roles"]

    if role.id in lst:
        lst.remove(role.id)
        verb = "removed"
    else:
        lst.append(role.id)
        verb = "added"

    save_config(config)
    await interaction.response.send_message(f"{role.mention} {verb}", ephemeral=True)

bot.tree.add_command(g)
bot.run(os.getenv("DISCORD_TOKEN"))
