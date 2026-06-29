"""
================================================================================
                    TELEGRAM ADVANCED REFERRAL BOT SYSTEM
         [ Upgraded Production Engine - High Traffic & Safe Logs ]
================================================================================
"""

import os
import sys
import json
import hmac
import asyncio
import hashlib
import logging
import urllib.parse
from datetime import datetime

import httpx
import uvicorn
import aiosqlite
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, Router, F
from aiogram.enums import ParseMode, ChatMemberStatus
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton,
    WebAppInfo
)

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ReferralBotSystem")

BOT_TOKEN            = os.getenv("BOT_TOKEN", "")
ADMIN_IDS            = [int(x) for x in os.getenv("ADMIN_IDS", "0").split(",") if x.strip()]
PAYMENT_LOG_CHANNEL  = os.getenv("PAYMENT_LOG_CHANNEL", "").strip()
WEBAPP_URL           = os.getenv("WEBAPP_URL", "http://localhost:8000").rstrip("/")
PROXYCHECK_API_KEY   = os.getenv("PROXYCHECK_API_KEY", "")
DB_PATH              = "referral_bot.db"

# 🟢 FIX: Telebirr proof image file_id — used in the "Withdrawal Completed" proof post.
# This was missing, which is why send_photo had nothing to send and the code had
# fallen back to a text-only send_message.
TELEBIRR_PROOF_IMAGE = "AgACAgQAAxkBAAO6akLJQYxDTMsMCF_TJ1mfprGQg9oAAqgOaxv6JBFSsp0Sw79o0x0BAAMCAAN4AAM8BA"

if not WEBAPP_URL.startswith(("http://", "https://")):
    WEBAPP_URL = f"https://{WEBAPP_URL}"

BOT_RULES_CAPTION = (
    "📜 <b>System Terms of Service & Anti-Fraud Policy</b>\n\n"
    "1. <b>Strict Integrity:</b> Self-referrals or multi-accounting schemes are prohibited.\n"
    "2. <b>Security Protocols:</b> Use of VPNs, proxy networks, or emulators is banned.\n"
    "3. <b>Reward Settlement:</b> Rewards are credited after Mini App identity clear.\n"
    "⚠️ <i>Note: Violations will result in a permanent ban.</i>"
)

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY,
    username    TEXT,
    full_name   TEXT,
    referred_by INTEGER,
    balance     REAL    DEFAULT 0,
    is_banned   INTEGER DEFAULT 0,
    joined_at   TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER UNIQUE,
    ip_address  TEXT,
    user_agent  TEXT,
    fingerprint TEXT,
    verified_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS withdrawals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    amount          REAL,
    full_name       TEXT,
    phone           TEXT,
    status          TEXT    DEFAULT 'pending',
    channel_post_id INTEGER DEFAULT 0,
    reason          TEXT    DEFAULT '',
    created_at      TEXT    DEFAULT (datetime('now')),
    resolved_at     TEXT
);

CREATE TABLE IF NOT EXISTS force_channels (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id   TEXT UNIQUE,
    channel_name TEXT,
    invite_link  TEXT,
    bot_added    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('reward_per_referral', '10');
INSERT OR IGNORE INTO settings (key, value) VALUES ('min_withdrawal', '50');
"""

# ─────────────────────────────────────────────────────────────────────────────
# DATA ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class DataEngine:
    @staticmethod
    async def init_database():
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    @staticmethod
    async def get_user(user_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            return await cur.fetchone()

    @staticmethod
    async def create_user(user_id: int, username: str, full_name: str, referred_by: int = None):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR IGNORE INTO users (user_id, username, full_name, referred_by) VALUES (?,?,?,?)",
                (user_id, username, full_name, referred_by),
            )
            await db.commit()

    @staticmethod
    async def add_balance(user_id: int, amount: float):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE users SET balance = ROUND(balance + ?, 2) WHERE user_id = ?", (amount, user_id)
            )
            await db.commit()

    @staticmethod
    async def get_referral_metrics(user_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            cur1 = await db.execute("SELECT COUNT(*) FROM users WHERE referred_by = ?", (user_id,))
            direct_count = (await cur1.fetchone())[0] or 0

            cur2 = await db.execute(
                "SELECT COUNT(*) FROM users WHERE referred_by IN "
                "(SELECT user_id FROM users WHERE referred_by = ?)", (user_id,)
            )
            tier2_count = (await cur2.fetchone())[0] or 0

            return direct_count, tier2_count

    @staticmethod
    async def get_all_invited_users(user_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT user_id, username, full_name, joined_at FROM users WHERE referred_by = ?", (user_id,))
            return await cur.fetchall()

    @staticmethod
    async def ban_user(user_id: int, status: int = 1):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE users SET is_banned = ? WHERE user_id = ?", (status, user_id)
            )
            await db.commit()

    @staticmethod
    async def full_clear_verification(user_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM verifications WHERE user_id = ?", (user_id,))
            await db.commit()

    @staticmethod
    async def inject_fake_verification(user_id: int):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO verifications (user_id, ip_address, user_agent, fingerprint) VALUES (?,?,?,?)",
                (user_id, "BYPASS_ADMIN", "BYPASS_ADMIN", f"BYPASS_{user_id}"),
            )
            await db.commit()

    @staticmethod
    async def is_verified(user_id: int) -> bool:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute("SELECT id FROM verifications WHERE user_id = ?", (user_id,))
            return (await cur.fetchone()) is not None

    @staticmethod
    async def save_verification(user_id: int, ip: str, ua: str, fingerprint: str):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO verifications (user_id, ip_address, user_agent, fingerprint) VALUES (?,?,?,?)",
                (user_id, ip, ua, fingerprint),
            )
            await db.commit()

    @staticmethod
    async def create_withdrawal(user_id: int, amount: float, full_name: str, phone: str) -> int:
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "INSERT INTO withdrawals (user_id, amount, full_name, phone) VALUES (?,?,?,?)",
                (user_id, amount, full_name, phone),
            )
            await db.commit()
            return cur.lastrowid

    @staticmethod
    async def get_withdrawal(wid: int):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM withdrawals WHERE id = ?", (wid,))
            return await cur.fetchone()

    @staticmethod
    async def update_withdrawal_status(wid: int, status: str, post_id: int = 0, reason: str = ""):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE withdrawals SET status=?, channel_post_id=?, reason=?, resolved_at=datetime('now') WHERE id=?",
                (status, post_id, reason, wid),
            )
            await db.commit()

    @staticmethod
    async def get_pending_withdrawals():
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM withdrawals WHERE status='pending' ORDER BY created_at")
            return await cur.fetchall()

    @staticmethod
    async def add_force_channel(channel_id: str, channel_name: str, invite_link: str, bot_added: int = 0):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO force_channels (channel_id, channel_name, invite_link, bot_added) VALUES (?,?,?,?)",
                (channel_id, channel_name, invite_link, bot_added),
            )
            await db.commit()

    @staticmethod
    async def get_force_channels():
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT * FROM force_channels")
            return await cur.fetchall()

    @staticmethod
    async def get_setting(key: str, default=None):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cur = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = await cur.fetchone()
            return row["value"] if row else default

    @staticmethod
    async def set_setting(key: str, value: str):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, value))
            await db.commit()

# ─────────────────────────────────────────────────────────────────────────────
# WORKFLOW STATES
# ─────────────────────────────────────────────────────────────────────────────
class UserWithdrawalWorkflow(StatesGroup):
    select_payout_gateway = State()
    input_cash_volume     = State()
    provide_mobile_digits = State()
    provide_account_title = State()
    payout_final_approval = State()

class AdminConsoleWorkflow(StatesGroup):
    modify_referral_bounty   = State()
    modify_minimum_cashout   = State()
    append_mandatory_id      = State()
    append_mandatory_title   = State()
    append_mandatory_url     = State()
    append_noadmin_link      = State()
    append_noadmin_title     = State()
    direct_balance_target_id = State()
    direct_balance_volume    = State()
    broadcast_intel_payload  = State()
    broadcast_confirmation   = State()
    lookup_individual_id     = State()
    banish_individual_id     = State()
    pardon_individual_full   = State()
    pardon_individual_std    = State()
    write_reject_reason      = State()

bot         = Bot(token=BOT_TOKEN, parse_mode=ParseMode.HTML)
dp          = Dispatcher(storage=MemoryStorage())
core_router = Router()

# ─────────────────────────────────────────────────────────────────────────────
# FORCE JOIN LOGIC
# ─────────────────────────────────────────────────────────────────────────────
async def inspect_compulsory_memberships(user_id: int) -> list:
    channels = await DataEngine.get_force_channels()
    unjoined = []
    for ch in channels:
        if ch["bot_added"] == 1:
            continue
        try:
            m = await bot.get_chat_member(chat_id=ch["channel_id"], user_id=user_id)
            if m.status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED, ChatMemberStatus.RESTRICTED):
                unjoined.append(dict(ch))
        except Exception:
            unjoined.append(dict(ch))
    return unjoined

async def enforce_membership_gate(event, user_id: int) -> bool:
    unjoined = await inspect_compulsory_memberships(user_id)

    is_callback = isinstance(event, CallbackQuery)
    current_data = event.data if is_callback else ""

    if not is_callback or current_data in ("ui_return_home", ""):
        all_channels = await DataEngine.get_force_channels()
        for ch in all_channels:
            if ch["bot_added"] == 1:
                if not any(x['channel_id'] == ch['channel_id'] for x in unjoined):
                    unjoined.append(dict(ch))

    if not unjoined:
        return True

    buttons = []
    for ch in unjoined:
        buttons.append([InlineKeyboardButton(text=f"➕ Join: {ch['channel_name']}", url=ch["invite_link"])])

    buttons.append([InlineKeyboardButton(text="✅ Joined / ተቀላቅያለሁ", callback_data="ui_revalidate_channels")])

    txt = "👋 <b>Welcome!</b>\n\nእባክዎ ከታች ያሉትን ሁሉንም ቻናሎች ይቀላቀሉ፣ ከዚያም <b>'Joined'</b> የሚለውን በተን ይጫኑ።\n\nPlease join all channels and continue."

    if isinstance(event, Message):
        await event.answer(txt, reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))
    elif isinstance(event, CallbackQuery):
        await event.message.answer(txt, reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))
        await event.answer()
    return False

@core_router.callback_query(F.data == "ui_revalidate_channels")
async def process_channel_revalidation(callback: CallbackQuery, state: FSMContext):
    uid = callback.from_user.id
    channels = await DataEngine.get_force_channels()

    real_unjoined = []
    for ch in channels:
        if ch["bot_added"] == 0:
            try:
                m = await bot.get_chat_member(chat_id=ch["channel_id"], user_id=uid)
                if m.status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED, ChatMemberStatus.RESTRICTED):
                    real_unjoined.append(ch)
            except Exception:
                real_unjoined.append(ch)

    if real_unjoined:
        return await callback.answer("❌ Please join all channels and continue.", show_alert=True)

    try: await callback.message.delete()
    except Exception: pass

    s = await state.get_data()
    ref = s.get("stashed_referrer_id", 0)
    await state.clear()

    if await DataEngine.is_verified(uid):
        await callback.message.answer("✅ Identity clear!", reply_markup=generate_dashboard_matrix(uid))
    else:
        sent = await callback.message.answer(f"{BOT_RULES_CAPTION}\n\n🔐 <b>Attestation Step:</b> Launch Mini App verification:", reply_markup=generate_verification_widget(uid, ref, 0))
        await sent.edit_reply_markup(reply_markup=generate_verification_widget(uid, ref, sent.message_id))

# ─────────────────────────────────────────────────────────────────────────────
# 🟢 FIX: CORE TELEGRAM BOT HANDLERS — these were completely missing from the
# code, which is why the bot never responded to /start or any main-menu button.
# ─────────────────────────────────────────────────────────────────────────────
@core_router.message(CommandStart())
async def process_start_command(message: Message, state: FSMContext):
    await state.clear()
    uid  = message.from_user.id
    args = message.text.split()
    arg  = args[1] if len(args) > 1 else ""
    ref  = int(arg) if arg.isdigit() and int(arg) != uid else 0

    acc = await DataEngine.get_user(uid)
    if acc and acc["is_banned"]:
        return await message.answer("🚫 <b>Banned:</b> Your profile has been blacklisted.")

    if not await enforce_membership_gate(message, uid):
        if ref: await state.update_data(stashed_referrer_id=ref)
        return

    if await DataEngine.is_verified(uid):
        return await message.answer("✅ <b>Welcome back!</b> Access granted.", reply_markup=generate_dashboard_matrix(uid))

    sent = await message.answer(f"{BOT_RULES_CAPTION}\n\n🔐 <b>Next Step:</b> Verify identity via Mini App:", reply_markup=generate_verification_widget(uid, ref, 0))
    await sent.edit_reply_markup(reply_markup=generate_verification_widget(uid, ref, sent.message_id))

@core_router.callback_query(F.data == "ui_return_home")
async def process_navigation_home(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    if not await enforce_membership_gate(callback, callback.from_user.id): return
    await callback.message.edit_text("🏠 <b>Main Dashboard Menu / ዋና ማውጫ</b>", reply_markup=generate_dashboard_matrix(callback.from_user.id))

@core_router.callback_query(F.data == "ui_fetch_balance")
async def process_balance_query(callback: CallbackQuery):
    if not await enforce_membership_gate(callback, callback.from_user.id): return
    acc   = await DataEngine.get_user(callback.from_user.id)
    min_w = await DataEngine.get_setting("min_withdrawal", "50")
    await callback.message.edit_text(f"💰 <b>Your Available Balance:</b>\n\n• Assets: <code>{float(acc['balance']):.2f} Birr</code>\n• Minimum Withdrawal: <code>{min_w} Birr</code>", reply_markup=generate_fallback_navigation())

@core_router.callback_query(F.data == "ui_fetch_referrals")
async def process_referral_query(callback: CallbackQuery):
    if not await enforce_membership_gate(callback, callback.from_user.id): return
    uid  = callback.from_user.id
    direct, _ = await DataEngine.get_referral_metrics(uid)
    rate = float(await DataEngine.get_setting("reward_per_referral", "10"))
    me   = await bot.get_me()
    link = f"https://t.me/{me.username}?start={uid}"
    await callback.message.edit_text(f"👥 <b>Your Referral Network:</b>\n\n• Total Referrals: <b>{direct} users</b>\n• Earnings per Referral: <b>{rate:.2f} Birr</b>\n• Total Earned: <b>{direct * rate:.2f} Birr</b>\n\n🔗 Your link:\n<code>{link}</code>", reply_markup=generate_fallback_navigation())

@core_router.callback_query(F.data == "ui_fetch_link")
async def process_link_generation(callback: CallbackQuery):
    if not await enforce_membership_gate(callback, callback.from_user.id): return
    me = await bot.get_me()
    await callback.message.edit_text(f"🔗 <b>Your Invite Link:</b>\n\n<code>https://t.me/{me.username}?start={callback.from_user.id}</code>", reply_markup=generate_fallback_navigation())

# ─────────────────────────────────────────────────────────────────────────────
# 🟢 ADMIN UTILITY: Get file_id from a photo (Admin sends a photo in private
# chat to the bot, bot replies with the file_id — copy this into
# TELEBIRR_PROOF_IMAGE to fix the proof channel photo post).
# ─────────────────────────────────────────────────────────────────────────────
@core_router.message(F.photo)
async def process_get_file_id(message: Message):
    if not evaluate_admin_access(message.from_user.id): return
    file_id = message.photo[-1].file_id
    await message.answer(
        f"📸 <b>File ID Captured:</b>\n\n<code>{file_id}</code>\n\n"
        f"⚠️ Copy this value and replace <code>TELEBIRR_PROOF_IMAGE</code> in the code with it."
    )

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def evaluate_admin_access(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def parse_telegram_webapp_handshake(init_data: str) -> dict | None:
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data, strict_parsing=True))
        vh = parsed.pop("hash", "")
        check_str = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
        key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        sig = hmac.new(key, check_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, vh): return None
        return json.loads(parsed.get("user", "{}"))
    except Exception: return None

async def execute_network_vpn_lookup(client_ip: str) -> bool:
    if not client_ip or client_ip in ("127.0.0.1", "::1", "unknown"): return False
    try:
        param = f"&key={PROXYCHECK_API_KEY}" if PROXYCHECK_API_KEY else ""
        url   = f"https://proxycheck.io/v2/{client_ip}?vpn=1{param}"
        async with httpx.AsyncClient(timeout=4) as c:
            r = await c.get(url)
            return r.json().get(client_ip, {}).get("proxy") == "yes"
    except Exception: return False

def generate_verification_widget(user_id: int, ref: int, msg_id: int = 0):
    url = f"{WEBAPP_URL}/verify?uid={user_id}&ref={ref}&msg_id={msg_id}"
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🔐 Open Mini App & Verify", web_app=WebAppInfo(url=url))
    ]])

def generate_dashboard_matrix(user_id: int) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(text="💰 Balance / ሒሳብ",    callback_data="ui_fetch_balance"),
            InlineKeyboardButton(text="👥 Referrals / ጋባዦች", callback_data="ui_fetch_referrals"),
        ],
        [
            InlineKeyboardButton(text="🔗 My Link / ሊንኬ", callback_data="ui_fetch_link"),
            InlineKeyboardButton(text="💸 Withdraw / ብር ማውጫ", callback_data="ui_initiate_withdrawal"),
        ],
    ]
    if evaluate_admin_access(user_id):
        rows.append([InlineKeyboardButton(text="⚙️ Admin Control Center", callback_data="ui_admin_core")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def generate_admin_dashboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💎 Set Referral Reward",  callback_data="adm_cmd_reward"), InlineKeyboardButton(text="💵 Set Min Withdrawal",   callback_data="adm_cmd_min_wd")],
        [InlineKeyboardButton(text="✍️ Edit User Balance",  callback_data="adm_cmd_edit_bal"), InlineKeyboardButton(text="📊 Bot Statistics",     callback_data="adm_cmd_stats")],
        [InlineKeyboardButton(text="🔴 Force Join (Real Admin)", callback_data="adm_cmd_add_mand"), InlineKeyboardButton(text="🟡 Fake Join (No Admin)", callback_data="adm_cmd_add_noadmin")],
        [InlineKeyboardButton(text="🗑 Remove Force Channel",       callback_data="adm_cmd_rm_node")], [InlineKeyboardButton(text="📋 List Force Channels",        callback_data="adm_cmd_list_channels")],
        [InlineKeyboardButton(text="📥 Pending Withdrawals",  callback_data="adm_cmd_pending_tickets"), InlineKeyboardButton(text="📢 Broadcast Message",    callback_data="adm_cmd_broadcast")],
        [InlineKeyboardButton(text="🔍 Search User",   callback_data="adm_cmd_search")],
        [InlineKeyboardButton(text="🚫 Ban User",    callback_data="adm_cmd_search"), InlineKeyboardButton(text="✅ Unban User Dashboard",  callback_data="adm_cmd_unban_menu")],
        [InlineKeyboardButton(text="🛑 STOP BOT ENGINE", callback_data="adm_stop_bot_confirm1")],
        [InlineKeyboardButton(text="🔙 Back to Main Menu", callback_data="ui_return_home")],
    ])

def generate_fallback_navigation(target="ui_return_home") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Back / ተመለስ", callback_data=target)]])

# ─────────────────────────────────────────────────────────────────────────────
# WITHDRAWAL CORE LOGIC & PROOF CHANNEL INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────
@core_router.callback_query(F.data == "ui_initiate_withdrawal")
async def process_withdrawal_start(callback: CallbackQuery, state: FSMContext):
    if not await enforce_membership_gate(callback, callback.from_user.id): return
    user  = await DataEngine.get_user(callback.from_user.id)
    min_w = float(await DataEngine.get_setting("min_withdrawal", "50"))

    current_bal = round(float(user["balance"]), 2)
    if current_bal < min_w:
        return await callback.answer(f"❌ Minimum payout baseline is {min_w:.2f} Birr. Your balance is {current_bal:.2f} Birr.", show_alert=True)

    await state.set_state(UserWithdrawalWorkflow.select_payout_gateway)
    await state.update_data(cached_balance=current_bal, cached_minimum=min_w)
    await callback.message.edit_text("💸 <b>Select Payout Endpoint:</b>", reply_markup=InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📲 Telebirr / ቴሌብር", callback_data="gateway_telebirr")],
        [InlineKeyboardButton(text="❌ Cancel / ሰርዝ",      callback_data="ui_return_home")],
    ]))

@core_router.callback_query(F.data == "gateway_telebirr", UserWithdrawalWorkflow.select_payout_gateway)
async def process_telebirr_selection(callback: CallbackQuery, state: FSMContext):
    await state.set_state(UserWithdrawalWorkflow.input_cash_volume)
    await callback.message.edit_text("<b>Specify the amount you wish to withdraw (Birr):</b>", reply_markup=generate_fallback_navigation())

@core_router.message(UserWithdrawalWorkflow.input_cash_volume)
async def process_cashout_volume(message: Message, state: FSMContext):
    s = await state.get_data()
    try:
        val = round(float(message.text.strip()), 2)
        if val < s["cached_minimum"] or val > s["cached_balance"]:
            return await message.answer(f"❌ Invalid amount. Minimum withdrawal is {s['cached_minimum']:.2f} ETB.\n⚠️ <b>Your balance is:</b> {s['cached_balance']:.2f} ETB.")
    except Exception:
        return await message.answer(f"❌ Please enter a valid number.\n⚠️ <b>Your balance is:</b> {s['cached_balance']:.2f} ETB.")

    await state.update_data(validated_volume=val)
    await state.set_state(UserWithdrawalWorkflow.provide_mobile_digits)
    await message.answer("📱 <b>Provide Destination Account Mobile Number:</b>")

@core_router.message(UserWithdrawalWorkflow.provide_mobile_digits)
async def process_mobile_digits(message: Message, state: FSMContext):
    phone = message.text.strip()
    if len(phone) < 9: return await message.answer("❌ Provide a valid mobile number.")
    await state.update_data(validated_phone=phone)
    await state.set_state(UserWithdrawalWorkflow.provide_account_title)
    await message.answer("📝 <b>Enter Full Name of Account Holder:</b>")

@core_router.message(UserWithdrawalWorkflow.provide_account_title)
async def process_account_title(message: Message, state: FSMContext):
    title = message.text.strip()
    if len(title) < 3: return await message.answer("❌ Name is too short.")
    await state.update_data(validated_title=title)
    s = await state.get_data()
    await message.answer(
        f"⚠️ <b>Review Settlement Details</b>\n\n• Platform: <code>Telebirr</code>\n• Amount: <code>{s['validated_volume']:.2f} ETB</code>\n• Holder: <code>{title}</code>\n• Number: <code>{s['validated_phone']}</code>\n\nAuthorization requested.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="✅ Transact Payout",  callback_data="action_payout_dispatch"),
            InlineKeyboardButton(text="❌ Abort / ሰርዝ",     callback_data="ui_return_home"),
        ]])
    )
    await state.set_state(UserWithdrawalWorkflow.payout_final_approval)

@core_router.callback_query(F.data == "action_payout_dispatch", UserWithdrawalWorkflow.payout_final_approval)
async def process_payout_dispatch(callback: CallbackQuery, state: FSMContext):
    s    = await state.get_data()
    uid  = callback.from_user.id
    user = await DataEngine.get_user(uid)

    if round(float(user["balance"]), 2) < s["validated_volume"]:
        return await callback.answer("❌ Insufficient funds.", show_alert=True)

    tid = await DataEngine.create_withdrawal(uid, s["validated_volume"], s["validated_title"], s["validated_phone"])
    await DataEngine.add_balance(uid, -s["validated_volume"])
    await state.clear()

    me = await bot.get_me()
    proof_channel_keyboard = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🚀 Invite Now", url=f"https://t.me/{me.username}?start={uid}")
    ]])

    post_id = 0
    if PAYMENT_LOG_CHANNEL:
        try:
            txt = (
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"📥 <b>NEW WITHDRAWAL REQUEST</b>\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"👤 <b>Account Holder Name:</b> {s['validated_title']}\n\n"
                f"🆔 <b>User ID:</b> <code>{uid}</code>\n\n"
                f"💰 <b>Requested Amount:</b> ETB {s['validated_volume']:.2f}\n\n"
                f"📱 <b>Method:</b> Telebirr Portal\n\n"
                f"📊 <b>Status:</b> Pending Verification ⏳\n\n"
                f"⏰ <b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━"
            )
            receipt = await bot.send_message(PAYMENT_LOG_CHANNEL, txt, reply_markup=proof_channel_keyboard)
            post_id = receipt.message_id
            await DataEngine.update_withdrawal_status(tid, "pending", post_id)
        except Exception as e:
            logger.error(f"Log Channel Post Error: {e}")

    direct_ref, tier2_ref = await DataEngine.get_referral_metrics(uid)
    alias_str = f"@{user['username']}" if user["username"] else "None"
    admin_txt = (
        f"📥 <b>Incoming Ticket #{tid}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 <b>Holder Name:</b> {s['validated_title']}\n"
        f"🆔 <b>User ID:</b> <code>{uid}</code>\n"
        f"👤 <b>Username:</b> {alias_str}\n"
        f"📲 <b>Phone:</b> <code>{s['validated_phone']}</code>\n"
        f"💰 <b>Amount:</b> <b>{s['validated_volume']:.2f} Birr</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📊 <b>NETWORK INTEGRITY REPORT:</b>\n"
        f"• Direct Referrals: <b>{direct_ref} ሰዎችን</b>\n"
        f"• Tier-2 Network Activity: <b>{tier2_ref} ሰዎችን</b>"
    )
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Approve (ይለቀቅ)",  callback_data=f"adm_payout_ap_{tid}"),
            InlineKeyboardButton(text="❌ Deny (ውድቅ አድርግ)",     callback_data=f"adm_payout_rjmenu_{tid}"),
        ],
        [InlineKeyboardButton(text="👥 View Referrals (የጋበዛቸውን ተመልከት)", callback_data=f"adm_view_invites_{uid}")]
    ])
    for aid in ADMIN_IDS:
        try: await bot.send_message(aid, admin_txt, reply_markup=markup)
        except Exception: pass

    await callback.message.edit_text("📨 <b>Withdrawal Submitted!</b> Processing within 2-24 hours.", reply_markup=generate_dashboard_matrix(uid))

# ─────────────────────────────────────────────────────────────────────────────
# VIEW REFERRALS CORE LOGIC FOR ADMIN
# ─────────────────────────────────────────────────────────────────────────────
@core_router.callback_query(F.data.startswith("adm_view_invites_"))
async def process_admin_view_invites(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    target_uid = int(callback.data.split("_")[3])

    invited_nodes = await DataEngine.get_all_invited_users(target_uid)
    if not invited_nodes:
        return await callback.answer("📭 This user has not invited anyone yet.", show_alert=True)

    lines = []
    for idx, node in enumerate(invited_nodes, 1):
        uname = f"@{node['username']}" if node['username'] else "No Username"
        lines.append(f"{idx}. {node['full_name']} ({uname}) - ID: <code>{node['user_id']}</code>\n📅 Joined: {node['joined_at']}")

    chunk_txt = f"👥 <b>List of Invited Users for ID {target_uid}:</b>\n\n" + "\n\n".join(lines)
    if len(chunk_txt) > 4000:
        chunk_txt = chunk_txt[:4000] + "\n\n⚠️...List truncated due to length limits."

    await bot.send_message(chat_id=callback.from_user.id, text=chunk_txt, reply_markup=generate_fallback_navigation("ui_admin_core"))
    await callback.answer()

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN APPROVE MANAGEMENT
# 🟢 FIX APPLIED HERE: now sends the Telebirr proof PHOTO (with the completed
# caption) as a reply to the original pending request post in the proof
# channel — instead of a text-only message.
# ─────────────────────────────────────────────────────────────────────────────
@core_router.callback_query(F.data.startswith("adm_payout_ap_"))
async def process_admin_approval(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    tid    = int(callback.data.split("_")[3])
    ticket = await DataEngine.get_withdrawal(tid)
    if not ticket or ticket["status"] != "pending": return await callback.answer("Already processed.")

    await DataEngine.update_withdrawal_status(tid, "approved", ticket["channel_post_id"])

    me = await bot.get_me()
    proof_channel_keyboard = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🚀 Invite Now", url=f"https://t.me/{me.username}?start={ticket['user_id']}")
    ]])

    # 🔥 Completed proof post (WITH PHOTO) sent as a Reply to the original
    # pending-request post in the proof channel.
    if PAYMENT_LOG_CHANNEL and ticket["channel_post_id"]:
        txt = (
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"✅ <b>WITHDRAWAL COMPLETED</b>\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"👤 <b>Recipient:</b> {ticket['full_name']}\n\n"
            f"💰 <b>Amount:</b> ETB {ticket['amount']:.2f}\n\n"
            f"🚀 <b>Operational Registry:</b> Success ✅\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━"
        )
        try:
            await bot.send_photo(
                chat_id=PAYMENT_LOG_CHANNEL,
                photo=TELEBIRR_PROOF_IMAGE,
                caption=txt,
                reply_to_message_id=ticket["channel_post_id"],  # ለድሮው ፖስት በ Reply ይላካል!
                reply_markup=proof_channel_keyboard
            )
        except Exception as e:
            # 🟢 FIX: Photo file_id failed (likely invalid/expired/belongs to a
            # different bot). Fall back to a text-only reply so the channel
            # ALWAYS gets a completion post — it never silently does nothing.
            logger.error(f"Proof Channel Photo Post Error (falling back to text): {e}")
            try:
                await bot.send_message(
                    chat_id=PAYMENT_LOG_CHANNEL,
                    text=txt,
                    reply_to_message_id=ticket["channel_post_id"],
                    reply_markup=proof_channel_keyboard
                )
            except Exception as e2:
                logger.error(f"Proof Channel Text Fallback Post Error: {e2}")

    try: await bot.send_message(ticket["user_id"], f"🎉 Your cashout of {ticket['amount']:.2f} Birr has been successfully approved and sent via Telebirr!")
    except Exception: pass
    await callback.message.edit_text(callback.message.text + "\n\n✅ Ticket Approved.")

@core_router.callback_query(F.data.startswith("adm_payout_rjmenu_"))
async def process_admin_rejection_menu(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    tid = int(callback.data.split("_")[3])

    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🤖 Multi-bot / Clone Account", callback_data=f"rj_select_{tid}_multi_bot")],
        [InlineKeyboardButton(text="❌ Fake Activity / Emulators", callback_data=f"rj_select_{tid}_fake_activity")],
        [InlineKeyboardButton(text="👥 በቂ ሰው አልጋበዘም (No Invites)", callback_data=f"rj_select_{tid}_no_invites")],
        [InlineKeyboardButton(text="✍️ Write Custom Reason (በጽሁፍ)", callback_data=f"rj_select_{tid}_write_custom")],
        [InlineKeyboardButton(text="🔙 Cancel", callback_data="ui_admin_core")]
    ])
    await callback.message.edit_text("❌ <b>የውድቅ ማድረጊያ ምክንያት ይምረጡ ወይም ይጻፉ:</b>", reply_markup=markup)

@core_router.callback_query(F.data.startswith("rj_select_"))
async def process_reason_selection(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    parts = callback.data.split("_")
    tid = int(parts[2])
    choice = "_".join(parts[3:])

    ticket = await DataEngine.get_withdrawal(tid)
    if not ticket or ticket["status"] != "pending": return await callback.answer("Already processed.")

    if choice == "write_custom":
        await state.set_state(AdminConsoleWorkflow.write_reject_reason)
        await state.update_data(active_reject_tid=tid)
        return await callback.message.edit_text("✍️ <b>እባክዎ ለተጠቃሚው የሚላከውን ምክንያት ይጻፉ:</b>")

    reason_map = {
        "multi_bot": "Multi-account / Clone system detected.",
        "fake_activity": "Fake verification / Fraudulent activity detected.",
        "no_invites": "Insufficient organic or active referrals."
    }
    reason = reason_map.get(choice, "Violated bot usage policies.")
    await execute_withdrawal_rejection(callback.message, tid, ticket, reason)

@core_router.message(AdminConsoleWorkflow.write_reject_reason)
async def process_custom_written_reason(message: Message, state: FSMContext):
    s = await state.get_data()
    await state.clear()
    tid = s["active_reject_tid"]
    ticket = await DataEngine.get_withdrawal(tid)
    if not ticket or ticket["status"] != "pending": return await message.answer("Ticket already processed.")

    reason = message.text.strip()
    await execute_withdrawal_rejection(message, tid, ticket, reason)

async def execute_withdrawal_rejection(msg_obj, tid, ticket, reason):
    await DataEngine.update_withdrawal_status(tid, "rejected", ticket["channel_post_id"], reason)

    warning_notice = (
        f"❌ <b>Your Withdrawal Request has been Rejected! / የክፍያ ጥያቄዎ ውድቅ ተደርጓል!</b>\n\n"
        f"💰 <b>Amount / መጠን:</b> <code>{ticket['amount']:.2f} Birr</code>\n"
        f"⚠️ <b>Reason / ምክንያት:</b> <code>{reason}</code>\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📢 <b>IMPORTANT NOTICE / ጠቃሚ ማሳሰቢያ:</b>\n"
        f"🇬🇧 Please invite real, organic, and active users to the bot. Fake, multi-accounts, or automated referral attempts are strictly monitored and will result in no payout and account ban.\n\n"
        f"🇪🇹 እባክዎ ወደ ቦቱ እውነተኛ እና ንቁ ተጠቃሚዎችን ብቻ ይጋብዙ። የሐሰት (Fake) አካውንቶችን፣ ራስን በራስ መጋበዝን (Multi-accounts) ወይም ሌላ የማጭበርበሪያ ዘዴዎችን መጠቀም ክፍያ እንደማያገኙ ያደርጋል፤ እንዲሁም ከመለያ እገዳ ሊጥልዎት ይችላል።\n"
        f"━━━━━━━━━━━━━━━━━━━━━━"
    )

    try: await bot.send_message(chat_id=ticket["user_id"], text=warning_notice)
    except Exception: pass

    if isinstance(msg_obj, Message):
        await msg_obj.answer(f"✅ Ticket #{tid} rejected. User notified in private mode. No channel post made.", reply_markup=generate_admin_dashboard())
    else:
        await msg_obj.edit_text(f"✅ Ticket #{tid} rejected. User notified in private mode. No channel post made.", reply_markup=generate_admin_dashboard())

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM MANAGEMENT & FRONTEND API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@core_router.callback_query(F.data == "ui_admin_core")
async def process_admin_panel(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    await callback.message.edit_text("⚙️ <b>Operational Admin Master Engine</b>", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_add_mand")
async def process_add_channel_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.append_mandatory_id)
    await callback.message.edit_text("🔴 <b>Force Join — Real Check (Bot Must Be Admin)</b>\nEnter Channel ID (e.g. <code>-1001234567890</code>):", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.append_mandatory_id)
async def process_add_channel_id(message: Message, state: FSMContext):
    await state.update_data(ch_id=message.text.strip())
    await state.set_state(AdminConsoleWorkflow.append_mandatory_title)
    await message.answer("📝 <b>Enter Channel Display Title:</b>")

@core_router.message(AdminConsoleWorkflow.append_mandatory_title)
async def process_add_channel_title(message: Message, state: FSMContext):
    await state.update_data(ch_title=message.text.strip())
    await state.set_state(AdminConsoleWorkflow.append_mandatory_url)
    await message.answer("🔗 <b>Enter Channel Invite Link:</b>")

@core_router.message(AdminConsoleWorkflow.append_mandatory_url)
async def process_add_channel_finalize(message: Message, state: FSMContext):
    s = await state.get_data()
    await state.clear()
    await DataEngine.add_force_channel(s["ch_id"], s["ch_title"], message.text.strip(), bot_added=0)
    await message.answer(f"✅ <b>Real Force channel added!</b>\n📌 {s['ch_title']}", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_add_noadmin")
async def process_add_noadmin_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.append_noadmin_link)
    await callback.message.edit_text("🟡 <b>Fake Join (ማስመሰያ - No Admin Required)</b>\n\nየቻናሉን <b>ሊንክ</b> አስገባ (e.g. https://t.me/xxxx):", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.append_noadmin_link)
async def process_noadmin_link(message: Message, state: FSMContext):
    await state.update_data(na_link=message.text.strip())
    await state.set_state(AdminConsoleWorkflow.append_noadmin_title)
    await message.answer("📝 <b>Enter Display Name for Fake Channel:</b>")

@core_router.message(AdminConsoleWorkflow.append_noadmin_title)
async def process_noadmin_title(message: Message, state: FSMContext):
    s = await state.get_data()
    await state.clear()
    fake_key = "fake_" + hashlib.md5(s["na_link"].encode()).hexdigest()[:8]
    await DataEngine.add_force_channel(channel_id=fake_key, channel_name=message.text.strip(), invite_link=s["na_link"], bot_added=1)
    await message.answer(f"✅ <b>Fake ማስመሰያ ቻናል ተጨምሯል!</b>\n📌 {message.text.strip()}", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_list_channels")
async def process_list_channels(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    channels = await DataEngine.get_force_channels()
    if not channels: return await callback.message.edit_text("📭 No channels configured.", reply_markup=generate_fallback_navigation("ui_admin_core"))
    lines = []
    for ch in channels:
        mode = "🟡 Fake" if ch["bot_added"] else "🔴 Real"
        lines.append(f"{mode} — <b>{ch['channel_name']}</b>\n🔗 {ch['invite_link']}")
    await callback.message.edit_text(f"📋 <b>Force Channels Inventory ({len(channels)})</b>\n\n" + "\n\n".join(lines), reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.callback_query(F.data == "adm_cmd_rm_node")
async def process_rm_channel_menu(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    channels = await DataEngine.get_force_channels()
    if not channels: return await callback.message.edit_text("📭 No channels to remove.", reply_markup=generate_fallback_navigation("ui_admin_core"))
    buttons = []
    for ch in channels:
        mode = "🟡" if ch["bot_added"] else "🔴"
        buttons.append([InlineKeyboardButton(text=f"🗑 {mode} {ch['channel_name']}", callback_data=f"execute_rm_node_{ch['id']}" )])
    buttons.append([InlineKeyboardButton(text="🔙 Back", callback_data="ui_admin_core")])
    await callback.message.edit_text("<b>Select channel to remove:</b>", reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))

@core_router.callback_query(F.data.startswith("execute_rm_node_"))
async def process_rm_channel_action(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    row_id = int(callback.data.replace("execute_rm_node_", ""))
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM force_channels WHERE id = ?", (row_id,))
        await db.commit()
    await callback.message.edit_text("✅ Channel configuration removed.", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_stop_bot_confirm1")
async def stop_bot_first_confirmation(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚠️ ኃላፊነቱን እወስዳለሁ - ቀጥል", callback_data="adm_stop_bot_confirm2")],
        [InlineKeyboardButton(text="❌ አቁም/ተመለስ", callback_data="ui_admin_core")]
    ])
    await callback.message.edit_text(
        "🚨 <b>FIRST WARNING / የመጀመሪያ ደረጃ ማስጠንቀቂያ!</b>\n\n"
        "ቦቱን ማቆም (Stop) ከፈለጉ እርግጠኛ ነዎት? ይህ ትዕዛዝ ሲፈጸም ቦቱ ከቴሌግራም ሰርቨር ጋር ያለው ግንኙነት ይቋረጣል!",
        reply_markup=markup
    )

@core_router.callback_query(F.data == "adm_stop_bot_confirm2")
async def stop_bot_final_confirmation(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🛑 አሁኑኑ ቦቱ ይጥፋ! (SHUTDOWN)", callback_data="adm_stop_bot_execute")],
        [InlineKeyboardButton(text="❌ ተመለስ", callback_data="ui_admin_core")]
    ])
    await callback.message.edit_text(
        "🛑 <b>FINAL CONFIRMATION / የመጨረሻ ማረጋገጫ!</b>\n\n"
        "ይህንን በተን ሲጫኑ የቦቱ የፖሊንግ ሲስተም (Polling Vector) ይዘጋል። ቦቱን በድጋሚ ለማስጀመር ሰርቨሩ ላይ መግባት ይኖርብዎታል!",
        reply_markup=markup
    )

@core_router.callback_query(F.data == "adm_stop_bot_execute")
async def execute_bot_shutdown(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    await callback.message.edit_text("💀 <b>Bot engine system is shutting down... Goodbye!</b>")
    sys.exit(0)

@core_router.callback_query(F.data == "adm_cmd_edit_bal")
async def process_edit_balance_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.direct_balance_target_id)
    await callback.message.edit_text("<b>Enter Targeted Telegram User ID:</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.direct_balance_target_id)
async def process_edit_balance_id(message: Message, state: FSMContext):
    await state.update_data(target_uid=int(message.text.strip()))
    await state.set_state(AdminConsoleWorkflow.direct_balance_volume)
    await message.answer("<b>Enter Adjustment Volume (e.g. 50 or -50):</b>")

@core_router.message(AdminConsoleWorkflow.direct_balance_volume)
async def process_edit_balance_final(message: Message, state: FSMContext):
    s = await state.get_data()
    await state.clear()
    await DataEngine.add_balance(s["target_uid"], float(message.text.strip()))
    await message.answer("✅ Balance metrics adjusted successfully.", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_stats")
async def process_stats(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*), SUM(balance) FROM users")
        row = await cur.fetchone()
    await callback.message.edit_text(f"📊 <b>Bot Network Core Analytics:</b>\n\n• Registered Users: <b>{row[0] or 0}</b>\n• Outstanding Liabilities: <b>{float(row[1] or 0.0):.2f} ETB</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.callback_query(F.data == "adm_cmd_search")
async def process_search_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.lookup_individual_id)
    await callback.message.edit_text("🔍 <b>Enter Target User Telegram ID:</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.lookup_individual_id)
async def process_search_execute(message: Message, state: FSMContext):
    await state.clear()
    target = int(message.text.strip())
    user = await DataEngine.get_user(target)
    if not user: return await message.answer("❌ User not found.", reply_markup=generate_admin_dashboard())
    direct, tier2 = await DataEngine.get_referral_metrics(target)
    await message.answer(
        f"👤 <b>User Matrix Profile:</b>\n\n• Name: {user['full_name']}\n• Alias: @{user['username'] or 'N/A'}\n• Balance: <b>{float(user['balance']):.2f} Birr</b>\n"
        f"• Direct Invites: <b>{direct}</b>\n• Tier-2 Network: <b>{tier2}</b>\n• Banned Status: <b>{'Yes' if user['is_banned'] else 'No'}</b>\n• Joined: {user['joined_at']}",
        reply_markup=generate_admin_dashboard()
    )

@core_router.callback_query(F.data == "adm_cmd_reward")
async def process_reward_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.modify_referral_bounty)
    await callback.message.edit_text("<b>Enter New Reward Per Referral (Birr):</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.modify_referral_bounty)
async def process_reward_execute(message: Message, state: FSMContext):
    await DataEngine.set_setting("reward_per_referral", message.text.strip())
    await state.clear()
    await message.answer("✅ Bounty update secured.", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_min_wd")
async def process_min_wd_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.modify_minimum_cashout)
    await callback.message.edit_text("<b>Enter New Minimum Cashout Threshold (Birr):</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.modify_minimum_cashout)
async def process_min_wd_execute(message: Message, state: FSMContext):
    await DataEngine.set_setting("min_withdrawal", message.text.strip())
    await state.clear()
    await message.answer("✅ Minimum baseline updated.", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_pending_tickets")
async def process_pending_inventory(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    pending = await DataEngine.get_pending_withdrawals()
    if not pending: return await callback.message.edit_text("📭 No pending withdrawals.", reply_markup=generate_fallback_navigation("ui_admin_core"))
    lines = [f"• <b>#{t['id']}</b> — {t['full_name']} — <code>{float(t['amount']):.2f} ETB</code>" for t in pending]
    await callback.message.edit_text(f"📥 <b>Pending Withdrawal Withdrawal Inventory ({len(pending)})</b>\n\n" + "\n".join(lines), reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.callback_query(F.data == "adm_cmd_broadcast")
async def process_broadcast_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.broadcast_intel_payload)
    await callback.message.edit_text("📢 <b>Enter Broadcast Payload Text (የሚላከውን ጽሁፍ ያስገቡ):</b>", reply_markup=generate_fallback_navigation("ui_admin_core"))

@core_router.message(AdminConsoleWorkflow.broadcast_intel_payload)
async def process_broadcast_preview(message: Message, state: FSMContext):
    text = message.text
    await state.update_data(bc_payload=text)
    await state.set_state(AdminConsoleWorkflow.broadcast_confirmation)

    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚀 አሁን አሰራጭ (Send Now)", callback_data="bc_action_confirm")],
        [InlineKeyboardButton(text="✍️ መልዕክቱን ቀይር (Edit)", callback_data="adm_cmd_broadcast")],
        [InlineKeyboardButton(text="❌ ሰርዝ (Cancel)", callback_data="ui_admin_core")]
    ])
    await message.answer(f"📝 <b>የመልዕክት ቅድመ-ዕይታ (Preview):</b>\n\n{text}\n\n⚠️ እርግጠኛ ነዎት ይህ መልዕክት ለሁሉም ተጠቃሚዎች እንዲሰራጭ ይፈልጋሉ?", reply_markup=markup)

@core_router.callback_query(F.data == "bc_action_confirm", AdminConsoleWorkflow.broadcast_confirmation)
async def process_broadcast_execute(callback: CallbackQuery, state: FSMContext):
    s = await state.get_data()
    text = s["bc_payload"]
    await state.clear()

    progress = await callback.message.edit_text("⏳ Dispersing broadcast vectors... እባክዎ ይጠብቁ...")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_id FROM users")
        nodes = await cur.fetchall()

    sc = 0
    for (uid,) in nodes:
        try:
            await bot.send_message(uid, text)
            sc += 1
            await asyncio.sleep(0.04)
        except Exception: pass

    await progress.delete()
    await callback.message.answer(f"✅ Transmission secure. Sent to {sc} active nodes.", reply_markup=generate_admin_dashboard())

@core_router.callback_query(F.data == "adm_cmd_unban_menu")
async def process_unban_dashboard(callback: CallbackQuery):
    if not evaluate_admin_access(callback.from_user.id): return
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Standard Unban (Requires MiniApp)", callback_data="unban_trigger_std")],
        [InlineKeyboardButton(text="🔥 Full Unban (Bypass MiniApp - Direct Menu)", callback_data="unban_trigger_full")],
        [InlineKeyboardButton(text="🔙 Back", callback_data="ui_admin_core")]
    ])
    await callback.message.edit_text("🔓 <b>የመፍቻ አይነት ይምረጡ / Select Unban Method:</b>\n\n• <b>Standard Unban:</b> እገዳውን ያነሳል፣ ነገር ግን ልክ እንደ መጀመሪያው ሲገባ የMini App ማረጋገጫ (Verification) ይጠይቃል።\n• <b>Full Unban:</b> ተጠቃሚውን ሙሉ በሙሉ ነፃ ያደርገዋል (Verification Passed)፤ ወደ ቦቱ ሲመለስ ምንም ማረጋገጫ ሳይጠይቅ በቀጥታ ወደ **ዋናው ማውጫ (Menu)** ይወስደዋል።", reply_markup=markup)

@core_router.callback_query(F.data == "unban_trigger_std")
async def process_std_unban_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.pardon_individual_std)
    await callback.message.edit_text("👤 <b>[Standard Unban] Enter Telegram User ID (Will request MiniApp Verification):</b>", reply_markup=generate_fallback_navigation("adm_cmd_unban_menu"))

@core_router.message(AdminConsoleWorkflow.pardon_individual_std)
async def process_std_unban_execute(message: Message, state: FSMContext):
    try:
        target = int(message.text.strip())
        await DataEngine.ban_user(target, 0)
        await DataEngine.full_clear_verification(target)
        await state.clear()
        await message.answer(f"✅ <b>Standard Unban Completed!</b> User ID <code>{target}</code> unbanned. Bot will request MiniApp verification upon entry.", reply_markup=generate_admin_dashboard())
    except ValueError:
        await message.answer("❌ Please provide a valid numeric User ID.")

@core_router.callback_query(F.data == "unban_trigger_full")
async def process_full_unban_start(callback: CallbackQuery, state: FSMContext):
    if not evaluate_admin_access(callback.from_user.id): return
    await state.set_state(AdminConsoleWorkflow.pardon_individual_full)
    await callback.message.edit_text("🔥 <b>[Full Unban] Enter Telegram User ID (Bypasses MiniApp - Direct Menu Access):</b>", reply_markup=generate_fallback_navigation("adm_cmd_unban_menu"))

@core_router.message(AdminConsoleWorkflow.pardon_individual_full)
async def process_full_unban_execute(message: Message, state: FSMContext):
    try:
        target = int(message.text.strip())
        await DataEngine.ban_user(target, 0)
        await DataEngine.inject_fake_verification(target)
        await state.clear()
        await message.answer(f"🚀 <b>Full Unban Completed!</b> User ID <code>{target}</code> is fully unbanned. Profile set to Verified (Direct Menu access granted).", reply_markup=generate_admin_dashboard())
    except ValueError:
        await message.answer("❌ Please provide a valid numeric User ID.")

# ─────────────────────────────────────────────────────────────────────────────
# FASTAPI APP & LIFESPAN MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def application_lifespan(app: FastAPI):
    await DataEngine.init_database()
    asyncio.create_task(dp.start_polling(bot, skip_updates=True))
    yield

api_platform = FastAPI(lifespan=application_lifespan)
dp.include_router(core_router)

api_platform.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@api_platform.get("/verify", response_class=HTMLResponse)
async def serve_frontend(uid: int = 0, ref: int = 0, msg_id: int = 0):
    try:
        with open("index.html") as f: html = f.read()
        return HTMLResponse(content=html.replace("__BACKEND_URL__", WEBAPP_URL))
    except Exception as e: raise HTTPException(status_code=500, detail=f"Frontend missing: {e}")

@api_platform.post("/api/verify")
async def execute_verification(request: Request):
    data = await request.json()
    tg_user = parse_telegram_webapp_handshake(data.get("initData", ""))
    if not tg_user: raise HTTPException(status_code=403, detail="Signature breach.")

    uid    = int(tg_user["id"])
    ref_id = int(data.get("refId") or 0)
    msg_id = int(data.get("msgId") or 0)

    if await DataEngine.is_verified(uid):
        return JSONResponse({"status": "already_verified"})

    fingerprint = data.get("fingerprint", "").strip()
    if not fingerprint or fingerprint in ("undefined", "null", ""):
        await DataEngine.create_user(uid, tg_user.get("username", ""), tg_user.get("first_name", ""))
        await DataEngine.ban_user(uid, 1)
        if msg_id > 0:
            try: await bot.delete_message(chat_id=uid, message_id=msg_id)
            except Exception: pass
        return JSONResponse({"status": "blocked", "reason": "clone"})

    client_ip = request.headers.get("X-Forwarded-For")
    if client_ip: client_ip = client_ip.split(",")[0].strip()
    else: client_ip = request.client.host if request.client else "unknown"

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT user_id FROM verifications WHERE fingerprint = ? AND ip_address = ? AND user_id != ? LIMIT 1",
            (fingerprint, client_ip, uid),
        )
        duplicate_identity = await cur.fetchone()

    if duplicate_identity:
        await DataEngine.create_user(uid, tg_user.get("username", ""), tg_user.get("first_name", ""))
        await DataEngine.ban_user(uid, 1)
        if msg_id > 0:
            try: await bot.delete_message(chat_id=uid, message_id=msg_id)
            except Exception: pass
        return JSONResponse({"status": "blocked", "reason": "clone"})

    is_vpn = data.get("isVpn") or await execute_network_vpn_lookup(client_ip)
    if is_vpn:
        return JSONResponse({"status": "blocked", "reason": "vpn"})

    if msg_id > 0:
        try: await bot.delete_message(chat_id=uid, message_id=msg_id)
        except Exception: pass

    await DataEngine.create_user(uid, tg_user.get("username", ""), tg_user.get("first_name", ""), ref_id or None)
    await DataEngine.save_verification(uid, client_ip, data.get("ua", ""), fingerprint)

    if ref_id and ref_id != uid:
        bounty = float(await DataEngine.get_setting("reward_per_referral", "10"))
        await DataEngine.add_balance(ref_id, bounty)
        try: await bot.send_message(ref_id, f"🎉 <b>Referral verified!</b> <code>+{bounty:.2f} Birr</code> credited.")
        except Exception: pass

    try: await bot.send_message(uid, "✅ <b>Verification Confirmed! Access Granted.</b>", reply_markup=generate_dashboard_matrix(uid))
    except Exception: pass

    return JSONResponse({"status": "verified"})

if __name__ == "__main__":
    uvicorn.run("bot:api_platform", host="0.0.0.0", port=8000, log_level="info")
