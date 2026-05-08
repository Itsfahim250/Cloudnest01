import json
import os
import time
import uuid
import smtplib
import random
import requests
import string
import urllib.parse
import base64
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import telebot
from telebot import apihelper
from telebot import types
from flask import Flask, jsonify, request, abort, redirect, make_response, session, Response, stream_with_context
from flask_cors import CORS
from dotenv import load_dotenv

# =============================================================================
# CONFIG & INITIALIZATION
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

BOT_TOKEN = (os.environ.get("BOT_TOKEN") or "").strip()
ADMIN_CHAT_IDS_RAW = (os.environ.get("ADMIN_CHAT_ID") or "").strip()

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable is required.")

ADMIN_CHAT_IDS = {x.strip() for x in ADMIN_CHAT_IDS_RAW.split(",") if x.strip()}

# SMTP CONFIG
SMTP_EMAIL = "cloudnestotp@gmail.com"
SMTP_PASSWORD = "smeu dhdn zdou yfwc"

DATA_DIR = os.path.join(BASE_DIR, "data")
USER_DATA_FILE = os.path.join(DATA_DIR, "users.json")
SESSION_FILE = os.path.join(DATA_DIR, "sessions.json")
WEB_DB_FILE = os.path.join(DATA_DIR, "websites.json")
TEMP_MAIL_FILE = os.path.join(DATA_DIR, "temp_mails.json")
PREMIUM_CODES_FILE = os.path.join(DATA_DIR, "premium_codes.json")
URL_DB_FILE = os.path.join(DATA_DIR, "short_urls.json")
PROXY_SESSIONS_FILE = os.path.join(DATA_DIR, "proxy_sessions.json")

os.makedirs(DATA_DIR, exist_ok=True)

# =============================================================================
# PYTHONANYWHERE PROXY FIX
# =============================================================================

bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None, threaded=False)
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

# =============================================================================
# EXTERNAL BACKEND CONFIGURATION
# =============================================================================
EXTERNAL_BASE_URL = "http://109.199.121.213:5000"
EXTERNAL_API_KEY = "LdAUCkf3fi2B"

# =============================================================================
# STORAGE & STATE
# =============================================================================
TEMP_AUTH_STATE = {}
DEV_OTPS = {}
ADMIN_PREM_STATE = {}

FREE_LIMITS = {
    "otp_sends": 50,
    "web_ops": 5,
    "url_shortener": 20,
    "web_source": 10
}

FREE_LIMITS_DISPLAY = {
    "otp_sends": "50 OTPs/month",
    "web_ops": "5 Websites/month",
    "url_shortener": "20 URLs/month",
    "web_source": "10 Source Fetches/month"
}

PREMIUM_DURATIONS = {
    "1d": 86400,
    "7d": 604800,
    "1m": 2592000,
    "1y": 31536000
}

# =============================================================================
# SECURITY: HTML ENCRYPTION SYSTEM
# =============================================================================
ENCRYPTION_SECRET = BOT_TOKEN + "CloudNest_Secure_Key_250"

def encrypt_html(html_content):
    try:
        html_bytes = html_content.encode('utf-8')
        encrypted_bytes = bytearray()
        for i, b in enumerate(html_bytes):
            encrypted_bytes.append(b ^ ord(ENCRYPTION_SECRET[i % len(ENCRYPTION_SECRET)]))
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        return html_content

def decrypt_html(encrypted_b64):
    try:
        encrypted_bytes = base64.b64decode(encrypted_b64)
        decrypted_bytes = bytearray()
        for i, b in enumerate(encrypted_bytes):
            decrypted_bytes.append(b ^ ord(ENCRYPTION_SECRET[i % len(ENCRYPTION_SECRET)]))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return encrypted_b64

# =============================================================================
# SECURE PROXY SESSION SYSTEM
# =============================================================================

def load_proxy_sessions():
    return load_json_file(PROXY_SESSIONS_FILE, {})

def save_proxy_sessions(data):
    save_json_file(PROXY_SESSIONS_FILE, data)

def create_proxy_session(api_key, ttl=3600):
    token = "ps_" + secrets.token_hex(32)
    sessions = load_proxy_sessions()
    sessions = {k: v for k, v in sessions.items() if v["expires"] > time.time()}
    sessions[token] = {"api_key": api_key, "expires": time.time() + ttl, "created_at": now_iso()}
    save_proxy_sessions(sessions)
    return token

def resolve_proxy_session(token):
    if not token or not token.startswith("ps_"):
        return None
    sessions = load_proxy_sessions()
    record = sessions.get(token)
    if not record:
        return None
    if record["expires"] < time.time():
        del sessions[token]
        save_proxy_sessions(sessions)
        return None
    return record["api_key"]

def revoke_proxy_session(token):
    sessions = load_proxy_sessions()
    sessions.pop(token, None)
    save_proxy_sessions(sessions)

def get_api_key_from_request(req):
    # JSON বডি থেকে ডাটা নেওয়ার চেষ্টা করবে
    data = req.get_json(silent=True) or {}
    
    # JSON, URL (args), অথবা Form Data থেকে API Key খুঁজবে
    direct_key = (
        data.get("api_key") 
        or req.args.get("api_key") 
        or req.form.get("api_key")
    )
    
    # যদি বডি বা URL-এ না পায়, তবে Header থেকে খুঁজবে
    if not direct_key:
        auth_header = req.headers.get("Authorization")
        if auth_header:
            direct_key = auth_header.replace("Bearer ", "").strip()
            
    if direct_key:
        return direct_key
        
    # যদি API Key না থাকে, তবে Session Token খুঁজবে
    session_token = (
        data.get("session_token")
        or req.args.get("session_token")
        or req.form.get("session_token")
        or req.cookies.get("cn_session")
    )
    
    if session_token:
        return resolve_proxy_session(session_token)
        
    return None

# =============================================================================
# HELPERS
# =============================================================================
def now_iso(): return datetime.now(timezone.utc).isoformat()

def load_json_file(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception: pass
    return default

def save_json_file(path, data):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    os.replace(tmp_path, path)

load_users = lambda: load_json_file(USER_DATA_FILE, {})
save_users = lambda data: save_json_file(USER_DATA_FILE, data)
load_sessions = lambda: load_json_file(SESSION_FILE, {})
save_sessions = lambda data: save_json_file(SESSION_FILE, data)
load_web_db = lambda: load_json_file(WEB_DB_FILE, {})
save_web_db = lambda data: save_json_file(WEB_DB_FILE, data)
load_temp_mails = lambda: load_json_file(TEMP_MAIL_FILE, {})
save_temp_mails = lambda data: save_json_file(TEMP_MAIL_FILE, data)
load_premium_codes = lambda: load_json_file(PREMIUM_CODES_FILE, {})
save_premium_codes = lambda data: save_json_file(PREMIUM_CODES_FILE, data)
load_urls = lambda: load_json_file(URL_DB_FILE, {})
save_urls = lambda data: save_json_file(URL_DB_FILE, data)

def is_admin(chat_id): return str(chat_id) in ADMIN_CHAT_IDS

def get_public_base_url():
    try:
        if request and request.url_root: return request.url_root.rstrip("/")
    except Exception: pass
    return "https://cloudnest.pythonanywhere.com"

def get_logged_in_user(chat_id):
    sessions = load_sessions()
    user_email = sessions.get(str(chat_id))
    if not user_email: return None, None
    users = load_users()
    return user_email, users.get(user_email)

def get_user_by_api_key(api_key):
    if not api_key: return None, None
    users = load_users()
    for user_email, info in users.items():
        if info.get("api_key") == api_key: return user_email, info
    return None, None

def is_premium(user_info, feature):
    prem_data = user_info.get("premium", {})
    now = time.time()
    if prem_data.get("all", 0) > now: return True
    if prem_data.get(feature, 0) > now: return True
    return False

def consume_feature(user_email, feature, amount=1):
    users = load_users()
    user_info = users.get(user_email, {})
    if is_premium(user_info, feature): return True, user_info

    now = datetime.now(timezone.utc)
    last_reset = user_info.get("usage_last_reset", "2000-01")
    if f"{last_reset[:7]}" != now.strftime("%Y-%m"):
        user_info["usage"] = {}
        user_info["usage_last_reset"] = now.strftime("%Y-%m")

    limit = FREE_LIMITS.get(feature, 0)
    used = (user_info.get("usage") or {}).get(feature, 0)
    if used + amount > limit: return False, user_info

    user_info.setdefault("usage", {})[feature] = used + amount
    users[user_email] = user_info
    save_users(users)
    return True, user_info

def usage_summary(user_info):
    lines =[]
    now = time.time()
    prem = user_info.get("premium", {})
    for feature, display in FREE_LIMITS_DISPLAY.items():
        if prem.get("all", 0) > now or prem.get(feature, 0) > now:
            lines.append(f"- {feature.replace('_', ' ').title()}: ♾️ Unlimited (Premium)")
        else:
            used = (user_info.get("usage") or {}).get(feature, 0)
            lines.append(f"- {feature.replace('_', ' ').title()}: {used} / {display}")
    lines.append("- Temp Mail: Unlimited")
    return "\n".join(lines)

# =============================================================================
# OTP EMAIL TEMPLATES
# =============================================================================
def send_premium_otp_email(to_email, otp_code):
    try:
        msg = MIMEMultipart("alternative")
        msg['Subject'] = f"{otp_code} is your CloudNest account recovery code"
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email

        html = f"""
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f0f2f5; padding: 40px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <tr>
                <td align="center">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%" max-width="500" style="background-color:#ffffff; border-radius:8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow:hidden; max-width: 500px;">
                        <tr>
                            <td align="center" style="background-color:#1877f2; padding:25px;">
                                <h1 style="color:#ffffff; margin:0; font-size:26px; font-weight: 700; letter-spacing: 1px;">CloudNest</h1>
                            </td>
                        </tr>
                        <tr>
                            <td align="center" style="padding:40px 30px;">
                                <h2 style="color:#1c1e21; font-size:20px; margin:0 0 15px 0; font-weight: 600;">Authentication Required</h2>
                                <p style="color:#606770; font-size:15px; margin:0 0 25px 0; line-height: 1.5;">You've requested a security code to verify your CloudNest Bot account. Please enter the code below:</p>
                                <div style="background-color:#e7f3ff; border:1px solid #1877f2; border-radius:6px; padding:15px 30px; display:inline-block; margin-bottom: 25px;">
                                    <span style="color:#1877f2; font-size:36px; font-weight:bold; letter-spacing:5px;">{otp_code}</span>
                                </div>
                                <p style="color:#8a8d91; font-size:13px; margin:0; line-height: 1.4;">If you didn't request this code, you can safely ignore this email. Someone else might have typed your email address by mistake.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        """
        msg.attach(MIMEText(html, "html"))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo(); server.starttls(); server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string()); server.quit()
        return True
    except: return False

def send_api_otp_email(to_email, otp_code, is_premium_user=False):
    try:
        msg = MIMEMultipart("alternative")
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email

        if is_premium_user:
            msg['Subject'] = f"{otp_code} — Your Verification Code"
            html = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f0f2f5;padding:40px 0;">
  <tr>
    <td align="center">
      <table width="500" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.08);max-width:500px;width:100%;">
        <tr>
          <td align="center" style="background:linear-gradient(135deg,#1877f2 0%,#0a5bbf 100%);padding:32px 24px;">
            <div style="display:inline-block;background:rgba(255,255,255,0.15);border-radius:12px;padding:10px 24px;">
              <span style="color:#ffffff;font-size:22px;font-weight:800;letter-spacing:2px;text-transform:uppercase;">CloudNest</span>
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:40px 40px 32px 40px;text-align:center;">
            <div style="width:56px;height:56px;background:#e7f3ff;border-radius:50%;margin:0 auto 20px;display:flex;align-items:center;justify-content:center;">
              <span style="font-size:26px;">🔐</span>
            </div>
            <h2 style="color:#1c1e21;font-size:22px;font-weight:700;margin:0 0 10px;">Security Verification</h2>
            <p style="color:#606770;font-size:14px;line-height:1.6;margin:0 0 28px;">Use this one-time code to complete your verification. Do not share it with anyone.</p>
            <div style="background:#f0f7ff;border:2px solid #1877f2;border-radius:10px;padding:18px 36px;display:inline-block;margin-bottom:28px;">
              <span style="color:#1877f2;font-size:40px;font-weight:800;letter-spacing:8px;font-family:'Courier New',monospace;">{otp_code}</span>
            </div>
            <p style="color:#bec3c9;font-size:12px;margin:0;line-height:1.5;">⏱ This code expires in <strong>5 minutes</strong>.<br>If you didn't request this, please ignore this email.</p>
          </td>
        </tr>
        <tr>
          <td style="background:#f7f8fa;padding:18px 40px;text-align:center;border-top:1px solid #e4e6ea;">
            <p style="color:#bec3c9;font-size:11px;margin:0;">This is an automated security message. Please do not reply.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>
            """
        else:
            msg['Subject'] = f"Your Verification Code: {otp_code}"
            html = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f6fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f6fb;padding:36px 0;">
  <tr>
    <td align="center">
      <table width="480" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.07);max-width:480px;width:100%;">
        <tr>
          <td style="background:#1877f2;height:5px;padding:0;font-size:0;line-height:0;">&nbsp;</td>
        </tr>
        <tr>
          <td style="padding:36px 36px 24px;text-align:center;">
            <p style="color:#606770;font-size:14px;margin:0 0 6px;">Your verification code is</p>
            <div style="background:#f0f7ff;border:1.5px solid #1877f2;border-radius:8px;padding:14px 32px;display:inline-block;margin:12px 0 20px;">
              <span style="color:#1877f2;font-size:38px;font-weight:800;letter-spacing:7px;font-family:'Courier New',monospace;">{otp_code}</span>
            </div>
            <p style="color:#8a8d91;font-size:13px;margin:0 0 4px;">Valid for <strong>5 minutes</strong>. Do not share this code.</p>
          </td>
        </tr>
        <tr>
          <td style="padding:0 36px;"><div style="border-top:1px solid #eaeaea;"></div></td>
        </tr>
        <tr>
          <td style="padding:20px 36px 28px;text-align:center;background:#fafbfc;">
            <p style="font-size:12px;color:#adb5bd;margin:0 0 10px;">Powered by</p>
            <div style="display:inline-block;background:#ffffff;border:1px solid #e4e6ea;border-radius:8px;padding:10px 22px;">
              <span style="font-size:15px;font-weight:700;color:#1877f2;letter-spacing:0.5px;">☁️ CloudNest</span>
              <span style="display:block;font-size:11px;color:#8a8d91;margin-top:4px;">
                Telegram Bot:&nbsp;
                <a href="https://t.me/CloudNest_Bot" style="color:#1877f2;text-decoration:none;font-weight:600;">@CloudNest_Bot</a>
              </span>
            </div>
            <p style="font-size:11px;color:#ced4da;margin:12px 0 0;">Upgrade to Premium for a watermark-free experience.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>
            """
        msg.attach(MIMEText(html, "html"))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo(); server.starttls(); server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string()); server.quit()
        return True
    except: return False

# =============================================================================
# TEMP MAIL TOOLS
# =============================================================================
MAIL_APIS = {
    "mail.tm": {"base_url": "https://api.mail.tm"},
    "mail.gw": {"base_url": "https://api.mail.gw"}
}
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def gen_str(l=10): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=l))
def gen_pass(l=12): return ''.join(random.choices(string.ascii_letters + string.digits, k=l)) + "Aa1@"

def create_temp_email_account(service="mail.tm"):
    services_to_try = [service]
    other = "mail.gw" if service == "mail.tm" else "mail.tm"
    if other not in services_to_try:
        services_to_try.append(other)

    for svc in services_to_try:
        api = MAIL_APIS.get(svc)
        if not api: continue
        base = api["base_url"]

        for attempt in range(3):
            try:
                domain_resp = requests.get(f"{base}/domains", headers=HEADERS, timeout=12)
                if domain_resp.status_code != 200:
                    time.sleep(1); continue

                domain_data = domain_resp.json()
                members = domain_data.get("hydra:member",[])
                if not members: break

                active_domains =[d for d in members if d.get("isActive", True)]
                if not active_domains: active_domains = members
                domain = active_domains[0].get("domain", "")
                if not domain: continue

                username = gen_str(14)
                acc_email = f"{username}@{domain}"
                password = gen_pass(14)

                create_resp = requests.post(f"{base}/accounts", json={"address": acc_email, "password": password}, headers=HEADERS, timeout=12)
                if create_resp.status_code == 422:
                    time.sleep(0.5); continue
                if create_resp.status_code not in (200, 201):
                    time.sleep(1); continue

                token_resp = requests.post(f"{base}/token", json={"address": acc_email, "password": password}, headers=HEADERS, timeout=12)
                if token_resp.status_code != 200:
                    time.sleep(1); continue

                token = token_resp.json().get("token", "")
                if not token: continue

                return {"email": acc_email, "password": password, "token": token, "service": svc}
            except Exception as e:
                time.sleep(1)
    return None

def get_temp_email_inbox(token, service):
    try:
        headers = HEADERS.copy()
        headers["Authorization"] = f"Bearer {token}"
        resp = requests.get(f"{MAIL_APIS[service]['base_url']}/messages", headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("hydra:member", [])
        return[]
    except Exception as e:
        return[]

# =============================================================================
# WEB SOURCE FETCHER
# =============================================================================
_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

def _is_blocked_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if host in _BLOCKED_HOSTS: return True
        if host.startswith("192.168.") or host.startswith("10.") or host.startswith("172."): return True
        if host == "169.254.169.254": return True
        return False
    except Exception: return True

_USER_AGENTS =[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def _build_fetch_headers(ua: str = None, referer: str = None) -> dict:
    if not ua: ua = random.choice(_USER_AGENTS)
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }
    if referer: headers["Referer"] = referer
    return headers

def _fetch_with_session(url: str, ua: str, timeout: int = 15) -> requests.Response:
    session_req = requests.Session()
    session_req.max_redirects = 10
    headers = _build_fetch_headers(ua=ua)
    resp = session_req.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=False)
    return resp

def _smart_fetch(target_url: str):
    for ua in[_USER_AGENTS[0], _USER_AGENTS[1]]:
        try:
            resp = _fetch_with_session(target_url, ua=ua, timeout=12)
            if resp.status_code < 500: return resp, "chrome_desktop", None
        except Exception:
            continue
    return None, None, "Failed to fetch source."

# =============================================================================
# KEYBOARDS
# =============================================================================
def auth_welcome_keyboard():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(types.KeyboardButton("Register"), types.KeyboardButton("Login"))
    return markup

def main_keyboard(chat_id):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    buttons =[
        types.KeyboardButton("📧 Temp Mail"),
        types.KeyboardButton("🌐 Your Websites"),
        types.KeyboardButton("⚙️ Project Settings"),
        types.KeyboardButton("💎 Redeem Premium"),
        types.KeyboardButton("Logout")
    ]
    if is_admin(chat_id):
        buttons.insert(0, types.KeyboardButton("🔑 Gen Premium"))
        buttons.append(types.KeyboardButton("🗑️ Clear Database"))
    markup.add(*buttons)
    return markup

# =============================================================================
# FLASK API ROUTES
# =============================================================================
@app.route(f"/webhook/{BOT_TOKEN}", methods=["POST"])
def webhook():
    if request.headers.get("content-type") == "application/json":
        update = telebot.types.Update.de_json(request.get_data().decode("utf-8"))
        bot.process_new_updates([update])
        return "", 200
    abort(403)

@app.route("/set_webhook", methods=["GET"])
def set_webhook():
    webhook_url = f"{get_public_base_url()}/webhook/{BOT_TOKEN}"
    bot.remove_webhook(); time.sleep(1)
    if bot.set_webhook(url=webhook_url): return f"Webhook set: {webhook_url}", 200
    return "Failed.", 500

# =============================================================================
# SECURE PROXY SESSION ENDPOINTS
# =============================================================================

@app.route("/api/auth/session", methods=["POST"])
def api_create_session():
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    ttl = min(int(data.get("ttl", 3600)), 86400)

    dev_email, user_info = get_user_by_api_key(api_key)
    if not dev_email:
        return jsonify({"status": "error", "message": "Invalid API Key."}), 401

    token = create_proxy_session(api_key, ttl)

    resp = make_response(jsonify({
        "status": "success",
        "session_token": token,
        "expires_in": ttl,
        "hint": "Use session_token instead of api_key in future requests."
    }))
    resp.set_cookie("cn_session", token, max_age=ttl, httponly=True, secure=True, samesite="Lax")
    return resp

@app.route("/api/auth/revoke", methods=["POST"])
def api_revoke_session():
    data = request.get_json(silent=True) or {}
    token = data.get("session_token") or request.cookies.get("cn_session")
    if token:
        revoke_proxy_session(token)
    resp = make_response(jsonify({"status": "success", "message": "Session revoked."}))
    resp.delete_cookie("cn_session")
    return resp

# =============================================================================
# EXISTING CLOUDNEST API ROUTES
# =============================================================================

@app.route("/api/otp/send", methods=["POST"])
def api_otp_send():
    data = request.get_json(silent=True) or {}
    target_email = data.get("email", "")

    api_key = get_api_key_from_request(request)
    dev_email, user_info = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"status": "error", "message": "Invalid API Key or Session."}), 401

    allowed, _ = consume_feature(dev_email, "otp_sends")
    if not allowed: return jsonify({"status": "error", "message": "OTP limit reached."}), 429

    otp_code = str(random.randint(100000, 999999))
    if send_api_otp_email(target_email, otp_code, is_premium_user=is_premium(user_info, "otp_sends")):
        DEV_OTPS[f"{api_key}_{target_email}"] = {"otp": otp_code, "expires": time.time() + 300}
        return jsonify({"status": "success", "message": "OTP sent."})
    return jsonify({"status": "error", "message": "Failed to send email."}), 500

@app.route("/api/otp/verify", methods=["POST"])
def api_otp_verify():
    data = request.get_json(silent=True) or {}
    target_email = data.get("email")
    otp = data.get("otp")

    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"status": "error", "message": "Invalid API Key or Session."}), 401

    key = f"{api_key}_{target_email}"
    record = DEV_OTPS.get(key)
    if not record or time.time() > record["expires"]:
        return jsonify({"status": "error", "message": "Expired or missing OTP."}), 400
    if record["otp"] == str(otp):
        del DEV_OTPS[key]
        return jsonify({"status": "success", "message": "OTP verified successfully."})
    return jsonify({"status": "error", "message": "Invalid OTP."}), 400

@app.route('/api/url/shorten', methods=['POST'])
def api_url_shorten():
    data = request.get_json(silent=True) or {}
    target_url = data.get("url")
    custom_slug = data.get("custom_slug")

    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401
    allowed, _ = consume_feature(dev_email, "url_shortener")
    if not allowed: return jsonify({"error": "Limit reached."}), 429

    urls_db = load_urls()
    if custom_slug:
        if custom_slug in urls_db or custom_slug in load_web_db():
            return jsonify({"error": "Name taken."}), 400
        slug = custom_slug
    else:
        while True:
            slug = gen_str(6)
            if slug not in urls_db and slug not in load_web_db(): break

    urls_db[slug] = {"url": target_url, "creator_api_key": api_key, "created_at": now_iso()}
    save_urls(urls_db)
    return jsonify({"status": "success", "short_url": f"{get_public_base_url()}/{slug}", "slug": slug})

@app.route('/api/web/upload', methods=['POST'])
def api_web_upload():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain")
    html_content = data.get("html_content")

    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"status": "error", "message": "Invalid API Key or Session."}), 401
    allowed, _ = consume_feature(dev_email, "web_ops")
    if not allowed: return jsonify({"status": "error", "message": "Website limit reached."}), 429

    db = load_web_db()
    if domain in db or domain in load_urls(): return jsonify({"error": "Name already exists."}), 400

    encrypted_html = encrypt_html(html_content)
    db[domain] = {"html_content": encrypted_html, "creator_api_key": api_key, "created_at": now_iso()}
    save_web_db(db)
    return jsonify({"status": "success", "url": f"{get_public_base_url()}/{domain}"})

@app.route('/api/web/update', methods=['POST'])
def api_web_update():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain")
    html_content = data.get("html_content")

    api_key = get_api_key_from_request(request)
    db = load_web_db()
    if domain not in db: return jsonify({"error": "Domain not found."}), 404
    if db[domain].get("creator_api_key") != api_key: return jsonify({"error": "Unauthorized."}), 403

    db[domain]["html_content"] = encrypt_html(html_content)
    save_web_db(db)
    return jsonify({"status": "success", "message": "Website updated."})

@app.route('/api/web/delete', methods=['POST'])
def api_web_delete():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain")

    api_key = get_api_key_from_request(request)
    db = load_web_db()
    if domain not in db: return jsonify({"error": "Domain not found."}), 404
    if db[domain].get("creator_api_key") != api_key: return jsonify({"error": "Unauthorized."}), 403

    del db[domain]; save_web_db(db)
    return jsonify({"status": "success", "message": "Website deleted."})

@app.route('/api/web/source', methods=['POST'])
def api_web_source():
    data = request.get_json(silent=True) or {}
    target_url = (data.get("url") or "").strip()

    if not target_url: return jsonify({"status": "error", "message": "URL is required."}), 400
    if not target_url.startswith(("http://", "https://")): target_url = "https://" + target_url
    if _is_blocked_url(target_url): return jsonify({"status": "error", "message": "Access to private/internal URLs is not allowed."}), 403

    api_key = get_api_key_from_request(request)
    dev_email, user_info = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"status": "error", "message": "Invalid API Key or Session."}), 401

    allowed, updated_info = consume_feature(dev_email, "web_source")
    if not allowed:
        used = (updated_info.get("usage") or {}).get("web_source", 0)
        return jsonify({
            "status": "error",
            "message": f"Web source fetch limit reached ({used}/10 per month). Upgrade to Premium for unlimited access.",
            "limit": 10, "used": used
        }), 429

    resp, strategy_used, error_msg = _smart_fetch(target_url)

    if resp is None:
        users = load_users()
        u = users.get(dev_email, {})
        if not is_premium(u, "web_source"):
            cur = (u.get("usage") or {}).get("web_source", 1)
            u.setdefault("usage", {})["web_source"] = max(0, cur - 1)
            users[dev_email] = u
            save_users(users)
        return jsonify({"status": "error", "message": error_msg or "Failed to fetch."}), 502

    encoding = resp.encoding or "utf-8"
    try: source_code = resp.content.decode(encoding, errors="replace")
    except Exception: source_code = resp.content.decode("utf-8", errors="replace")

    content_type = resp.headers.get("Content-Type", "text/html")
    final_url = resp.url
    status_code = resp.status_code
    size_bytes = len(resp.content)

    src_lower = source_code.lower()
    line_count = source_code.count("\n") + 1
    script_count = src_lower.count("<script")
    style_count = src_lower.count("<style")
    link_count = src_lower.count("<link")

    used_count = (updated_info.get("usage") or {}).get("web_source", 0)
    is_prem = is_premium(user_info, "web_source") or is_premium(user_info, "all")
    remaining = "unlimited" if is_prem else max(0, 10 - used_count)

    return jsonify({
        "status": "success",
        "original_url": target_url, "url": final_url, "redirected": final_url != target_url,
        "status_code": status_code, "content_type": content_type, "encoding": encoding, "size_bytes": size_bytes,
        "fetch_strategy": strategy_used,
        "metadata": {"line_count": line_count, "script_tags": script_count, "style_tags": style_count, "link_tags": link_count},
        "source_code": source_code,
        "usage": {"used_this_month": used_count, "limit": "unlimited" if is_prem else 10, "remaining": remaining}
    })

# =============================================================================
# EXTERNAL DB & AUTH PROXY ROUTES
# =============================================================================

def increment_usage(user_email, metric, amount=1):
    users = load_users()
    user_info = users.get(user_email)
    if user_info:
        ext_usage = user_info.get("ext_usage", {})
        ext_usage[metric] = ext_usage.get(metric, 0) + amount
        user_info["ext_usage"] = ext_usage
        save_users(users)

@app.route('/api/ext/auth/create', methods=['POST'])
def api_ext_auth_create():
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY, "Content-Type": "application/json"}
    try:
        resp = requests.post(f"{EXTERNAL_BASE_URL}/api/auth_create", json={}, headers=headers, timeout=20)
        if resp.status_code in [200, 201]:
            increment_usage(dev_email, "ext_auth_count")
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External Auth error: {str(e)}"}), 502

@app.route('/api/ext/auth/delete/<ext_api_key>', methods=['DELETE'])
def api_ext_auth_delete(ext_api_key):
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY}
    try:
        resp = requests.delete(f"{EXTERNAL_BASE_URL}/api/auth_delete/{ext_api_key}", headers=headers, timeout=20)
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External Auth error: {str(e)}"}), 502

@app.route('/api/ext/url/create', methods=['POST'])
def api_ext_url_create():
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY, "Content-Type": "application/json"}
    payload = request.get_json(silent=True) or {}
    
    payload.pop("api_key", None)
    payload.pop("session_token", None)
    
    try:
        resp = requests.post(f"{EXTERNAL_BASE_URL}/api/create_url", json=payload, headers=headers, timeout=20)
        if resp.status_code in[200, 201]:
            increment_usage(dev_email, "ext_url_count")
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External URL error: {str(e)}"}), 502

@app.route('/api/ext/url/delete/<short_id>', methods=['DELETE'])
def api_ext_url_delete(short_id):
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY}
    try:
        resp = requests.delete(f"{EXTERNAL_BASE_URL}/api/delete_url/{short_id}", headers=headers, timeout=20)
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External URL error: {str(e)}"}), 502

@app.route('/api/ext/db_reset', methods=['POST'])
def api_ext_db_reset():
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY, "Content-Type": "application/json"}
    try:
        resp = requests.post(f"{EXTERNAL_BASE_URL}/api/db_reset", json={}, headers=headers, timeout=20)
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External DB error: {str(e)}"}), 502

# =============================================================================
# EXTERNAL FILE PROXY ROUTES
# =============================================================================

@app.route('/api/ext/file/upload', methods=['POST'])
def api_ext_file_upload():
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400

    temp_dir = os.path.join(DATA_DIR, "temp")
    os.makedirs(temp_dir, exist_ok=True)
    filename = os.path.basename(file.filename)
    temp_path = os.path.join(temp_dir, f"{uuid.uuid4().hex}_{filename}")
    
    try:
        file.save(temp_path)
        file_size = os.path.getsize(temp_path)
        
        headers = {"Authorization": EXTERNAL_API_KEY}
        with open(temp_path, 'rb') as f:
            files_payload = {'file': (file.filename, f, file.content_type)}
            resp = requests.post(f"{EXTERNAL_BASE_URL}/api/upload", files=files_payload, headers=headers, timeout=120)
        
        if resp.status_code in[200, 201]:
            increment_usage(dev_email, "ext_file_count")
            increment_usage(dev_email, "ext_file_storage", file_size)
            
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External File Upload error: {str(e)}"}), 502
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

@app.route('/api/ext/file/delete/<file_id>', methods=['DELETE'])
def api_ext_file_delete(file_id):
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session."}), 401

    headers = {"Authorization": EXTERNAL_API_KEY}
    try:
        resp = requests.delete(f"{EXTERNAL_BASE_URL}/api/delete_file/{file_id}", headers=headers, timeout=20)
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get('Content-Type', 'application/json'))
    except Exception as e:
        return jsonify({"status": "error", "message": f"External File Delete error: {str(e)}"}), 502


# =============================================================================
# TEMP MAIL ROUTES
# =============================================================================

@app.route('/api/tempmail/create', methods=['GET'])
def api_tempmail_create():
    api_key = get_api_key_from_request(request)
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session"}), 401
    service = request.args.get("service", "mail.tm")
    account = create_temp_email_account(service)
    if not account: return jsonify({"error": "Failed to create temp email."}), 500
    all_mails = load_temp_mails(); all_mails.setdefault(api_key,[]).append(account); save_temp_mails(all_mails)
    return jsonify(account)

@app.route('/api/tempmail/inbox', methods=['GET'])
def api_tempmail_inbox():
    api_key = get_api_key_from_request(request)
    target_email = request.args.get("email")
    dev_email, _ = get_user_by_api_key(api_key)
    if not dev_email: return jsonify({"error": "Invalid API Key or Session"}), 401
    target_account = next((acc for acc in load_temp_mails().get(api_key,[]) if acc.get("email") == target_email), None)
    if not target_account: return jsonify({"error": "Access denied."}), 403
    return jsonify(get_temp_email_inbox(target_account['token'], target_account['service']))

# =============================================================================
# WEB SITE VIEW ROUTE
# =============================================================================

@app.route('/<path:slug_or_domain>')
def view_unified_route(slug_or_domain):
    urls_db = load_urls()
    if slug_or_domain in urls_db: return redirect(urls_db[slug_or_domain]["url"])

    db = load_web_db()
    site = db.get(slug_or_domain)
    if site:
        raw_html = decrypt_html(site["html_content"])
        protection_script = """
        <script>
            document.addEventListener('contextmenu', e => e.preventDefault());
            document.addEventListener('keydown', e => {
                if(e.keyCode === 123 || (e.ctrlKey && e.shiftKey &&[73, 74, 67].includes(e.keyCode)) || (e.ctrlKey && [85, 83].includes(e.keyCode))) {
                    e.preventDefault(); return false;
                }
            });
            setInterval(() => { (function() { return false; }['constructor']('debugger')()); }, 50);
        </script>
        """
        full_html = raw_html + protection_script
        salt = random.randint(10, 50)
        encoded_array =[(ord(char) + salt) for char in full_html]
        wrapper_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Loading Secure Content...</title>
            <script>
                (function(){{
                    var data = {encoded_array};
                    var s = {salt};
                    var output = '';
                    for(var i = 0; i < data.length; i++){{
                        output += String.fromCharCode(data[i] - s);
                    }}
                    document.open();
                    document.write(output);
                    document.close();
                }})();
            </script>
        </head>
        <body style="background:#fff; margin:0; padding:0;">
            <noscript>
                <div style="padding: 20px; font-family: sans-serif; text-align: center;">
                    Please enable JavaScript to view this secure content.
                </div>
            </noscript>
        </body>
        </html>
        """
        return wrapper_html

    return "404 Not Found", 404

# =============================================================================
# TELEGRAM BOT LOGIC
# =============================================================================

@bot.message_handler(commands=["start"])
def command_start(message):
    chat_id = str(message.chat.id)
    TEMP_AUTH_STATE.pop(chat_id, None)
    user_email, user_info = get_logged_in_user(chat_id)
    if user_email:
        text = f"🎉 Welcome back!\n\nYour API Key:\n<code>{user_info['api_key']}</code>"
        bot.send_message(chat_id, text, reply_markup=main_keyboard(chat_id), parse_mode="HTML")
    else:
        bot.send_message(chat_id, "Welcome to CloudNest! Please Register or Login.", reply_markup=auth_welcome_keyboard())

@bot.callback_query_handler(func=lambda call: call.data.startswith('admin_') or call.data.startswith('prem_'))
def handle_callbacks(call):
    chat_id = str(call.message.chat.id)
    if not is_admin(chat_id): return

    if call.data == "admin_clear_db":
        save_users({}); save_sessions({}); save_web_db({}); save_temp_mails({}); save_urls({}); save_premium_codes({}); save_proxy_sessions({})
        bot.edit_message_text("✅ <b>All Database Files Cleared Successfully!</b>", chat_id, call.message.message_id, parse_mode="HTML")
        return
    elif call.data == "admin_cancel_clear":
        bot.delete_message(chat_id, call.message.message_id)
        return

    parts = call.data.split('_', 2)
    action, value = parts[1], parts[2]

    if action == 'feat':
        ADMIN_PREM_STATE[chat_id] = {'feature': value}
        markup = types.InlineKeyboardMarkup().add(
            types.InlineKeyboardButton("1 Day", callback_data="prem_dur_1d"),
            types.InlineKeyboardButton("7 Days", callback_data="prem_dur_7d"),
            types.InlineKeyboardButton("1 Month", callback_data="prem_dur_1m"),
            types.InlineKeyboardButton("1 Year", callback_data="prem_dur_1y")
        )
        bot.edit_message_text("Select Validity Duration:", chat_id, call.message.message_id, reply_markup=markup)

    elif action == 'dur':
        if chat_id not in ADMIN_PREM_STATE: return
        feature = ADMIN_PREM_STATE[chat_id]['feature']
        code = f"CN-{uuid.uuid4().hex[:8].upper()}"
        codes_db = load_premium_codes()
        codes_db[code] = {"feature": feature, "duration": PREMIUM_DURATIONS.get(value, 86400)}
        save_premium_codes(codes_db)
        bot.edit_message_text(f"✅ Premium Code Generated!\n\nFeature: `{feature}`\nDuration: `{value}`\n\nCode:\n`{code}`", chat_id, call.message.message_id, parse_mode="Markdown")
        ADMIN_PREM_STATE.pop(chat_id, None)

@bot.message_handler(func=lambda message: True)
def handle_messages(message):
    chat_id = str(message.chat.id)
    text = (message.text or "").strip()
    if not text: return

    auth_state = TEMP_AUTH_STATE.get(chat_id)
    if auth_state:
        action, state = auth_state["action"], auth_state["state"]

        if action == "redeem_premium":
            code = text
            codes_db = load_premium_codes()
            if code not in codes_db:
                bot.send_message(chat_id, "❌ Invalid or expired Premium Code.")
                if text.lower() == 'cancel': TEMP_AUTH_STATE.pop(chat_id, None)
                return

            user_email, _ = get_logged_in_user(chat_id)
            prem_data = codes_db.pop(code); save_premium_codes(codes_db)
            feature, duration = prem_data["feature"], prem_data["duration"]

            users = load_users(); current_premium = users[user_email].get("premium", {})
            current_expiry = current_premium.get(feature, time.time())
            if current_expiry < time.time(): current_expiry = time.time()
            current_premium[feature] = current_expiry + duration
            users[user_email]["premium"] = current_premium; save_users(users)

            TEMP_AUTH_STATE.pop(chat_id, None)
            bot.send_message(chat_id, f"💎 Success! Premium applied for: **{feature.upper()}**", parse_mode="Markdown", reply_markup=main_keyboard(chat_id))
            return

        if action in ["register", "login"]:
            if state == "await_email":
                if "@" not in text or "." not in text:
                    bot.send_message(chat_id, "❌ Invalid email format."); return
                if action == "register" and text in load_users():
                    bot.send_message(chat_id, "❌ Email already registered.", reply_markup=auth_welcome_keyboard()); TEMP_AUTH_STATE.pop(chat_id, None); return
                if action == "login" and text not in load_users():
                    bot.send_message(chat_id, "❌ Email not found.", reply_markup=auth_welcome_keyboard()); TEMP_AUTH_STATE.pop(chat_id, None); return

                bot.send_message(chat_id, "Sending verification OTP...")
                otp = str(random.randint(100000, 999999))
                if send_premium_otp_email(text, otp):
                    TEMP_AUTH_STATE[chat_id].update({"email": text, "otp": otp, "state": "await_otp"})
                    bot.send_message(chat_id, "✅ OTP Sent! Check your email and enter the code:")
                else:
                    bot.send_message(chat_id, "❌ Failed to send OTP.", reply_markup=auth_welcome_keyboard()); TEMP_AUTH_STATE.pop(chat_id, None)
                return

            if state == "await_otp":
                if text != auth_state.get("otp"): bot.send_message(chat_id, "❌ Incorrect OTP."); return

                email = auth_state["email"]
                users, sessions = load_users(), load_sessions()

                if action == "register":
                    api_key = "cn_" + uuid.uuid4().hex
                    users[email] = {"email": email, "api_key": api_key, "created_at": now_iso(), "usage": {}, "premium": {}}
                    save_users(users)

                sessions[chat_id] = email; save_sessions(sessions)
                TEMP_AUTH_STATE.pop(chat_id, None)
                api_key = users[email]["api_key"]

                msg = f"🎉 Successfully {'Registered' if action == 'register' else 'Logged in'}!\n\nAPI Key:\n<code>{api_key}</code>"
                bot.send_message(chat_id, msg, reply_markup=main_keyboard(chat_id), parse_mode="HTML")
                return

    if text == "Register": TEMP_AUTH_STATE[chat_id] = {"action": "register", "state": "await_email"}; bot.send_message(chat_id, "Enter email to register:", reply_markup=types.ReplyKeyboardRemove()); return
    if text == "Login": TEMP_AUTH_STATE[chat_id] = {"action": "login", "state": "await_email"}; bot.send_message(chat_id, "Enter registered email:", reply_markup=types.ReplyKeyboardRemove()); return

    user_email, user_info = get_logged_in_user(chat_id)
    if not user_email: bot.send_message(chat_id, "You are not logged in.", reply_markup=auth_welcome_keyboard()); return

    if text == "Logout":
        sessions = load_sessions()
        if chat_id in sessions: del sessions[chat_id]; save_sessions(sessions)
        bot.send_message(chat_id, "✅ Logged out.", reply_markup=auth_welcome_keyboard())
        return

    if text == "💎 Redeem Premium":
        TEMP_AUTH_STATE[chat_id] = {"action": "redeem_premium", "state": "await_code"}
        bot.send_message(chat_id, "💎 Please enter Premium Code (or type Cancel):", reply_markup=types.ReplyKeyboardRemove())
        return

    if is_admin(chat_id):
        if text == "🔑 Gen Premium":
            markup = types.InlineKeyboardMarkup(row_width=2).add(
                types.InlineKeyboardButton("OTP Send", callback_data="prem_feat_otp_sends"),
                types.InlineKeyboardButton("Web Dev", callback_data="prem_feat_web_ops"),
                types.InlineKeyboardButton("URL Short", callback_data="prem_feat_url_shortener"),
                types.InlineKeyboardButton("🔍 Web Source", callback_data="prem_feat_web_source"),
                types.InlineKeyboardButton("👑 ALL Features", callback_data="prem_feat_all")
            )
            bot.send_message(chat_id, "Select Feature for Premium Code:", reply_markup=markup)
            return

        if text == "🗑️ Clear Database":
            markup = types.InlineKeyboardMarkup(row_width=2).add(
                types.InlineKeyboardButton("✅ Confirm Clear All", callback_data="admin_clear_db"),
                types.InlineKeyboardButton("❌ Cancel", callback_data="admin_cancel_clear")
            )
            bot.send_message(chat_id, "⚠️ <b>WARNING:</b> This will delete ALL users, websites, urls, and temp mails. Are you sure?", reply_markup=markup, parse_mode="HTML")
            return

    if text == "📧 Temp Mail":
        user_mails = load_temp_mails().get(user_info['api_key'],[])
        msg = "You have no temp emails." if not user_mails else "📧 Your Temp Emails:\n\n" + "\n".join([f"`{m['email']}`" for m in user_mails])
        bot.send_message(chat_id, msg, parse_mode="Markdown")

    elif text == "🌐 Your Websites":
        user_sites =[dom for dom, data in load_web_db().items() if data.get("creator_api_key") == user_info['api_key']]
        user_urls =[slug for slug, data in load_urls().items() if data.get("creator_api_key") == user_info['api_key']]
        msg = "🌐 Your Websites:\n" + ("None" if not user_sites else "\n".join([f"🔹 {get_public_base_url()}/{dom}" for dom in user_sites]))
        msg += "\n\n🔗 Your Short URLs:\n" + ("None" if not user_urls else "\n".join([f"🔸 {get_public_base_url()}/{s}" for s in user_urls]))
        bot.send_message(chat_id, msg + "\n\n" + usage_summary(user_info))

    elif text == "⚙️ Project Settings":
        api_key = user_info['api_key']
        base = get_public_base_url()
        ext_usage = user_info.get("ext_usage", {})
        ext_file_count = ext_usage.get("ext_file_count", 0)
        ext_file_storage = ext_usage.get("ext_file_storage", 0)
        ext_auth_count = ext_usage.get("ext_auth_count", 0)
        ext_url_count = ext_usage.get("ext_url_count", 0)

        if ext_file_storage < 1024: storage_str = f"{ext_file_storage} B"
        elif ext_file_storage < 1024**2: storage_str = f"{ext_file_storage/1024:.2f} KB"
        else: storage_str = f"{ext_file_storage/(1024**2):.2f} MB"

        inst = f"""☁️ CloudNest API — Quick Reference
Base URL: {base}
Your API Key: {api_key}

━━━━━━━━━━━━━━━━━━━━━━━━━
🗄️ EXT DB & AUTH (Proxy to Premium)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/ext/auth/create
  (Pass api_key in Session or URL)
DELETE /api/ext/auth/delete/<ext_api_key>?api_key={api_key}

POST /api/ext/url/create
  Body: {{"url": "https://...", "api_key": "{api_key}"}}
DELETE /api/ext/url/delete/<short_id>?api_key={api_key}

POST /api/ext/db_reset?api_key={api_key}

━━━━━━━━━━━━━━━━━━━━━━━━━
📁 EXT FILES (Proxy)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/ext/file/upload
  Form-Data: file=<your_file>, api_key="{api_key}"
DELETE /api/ext/file/delete/<file_id>?api_key={api_key}

━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 SESSION (Secure frontend use)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/auth/session
  Body: {{"api_key": "...", "ttl": 3600}}

━━━━━━━━━━━━━━━━━━━━━━━━━
📨 OTP (50/month free)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/otp/send
  Body: {{"api_key": "...", "email": "user@ex.com"}}

POST /api/otp/verify
  Body: {{"api_key": "...", "email": "...", "otp": "123456"}}

━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 WEB HOSTING (5/month free)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/web/upload
  Body: {{"api_key": "...", "domain": "mysite", "html_content": "<html>..."}}

━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 WEB SOURCE FETCHER (10/month)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/web/source
  Body: {{"api_key": "...", "url": "https://example.com"}}

━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 URL SHORTENER (20/month free)
━━━━━━━━━━━━━━━━━━━━━━━━━
POST /api/url/shorten
  Body: {{"api_key": "...", "url": "https://long.url", "custom_slug": "mylink"}}

━━━━━━━━━━━━━━━━━━━━━━━━━
📧 TEMP MAIL (Unlimited)
━━━━━━━━━━━━━━━━━━━━━━━━━
GET /api/tempmail/create?api_key=...&service=mail.tm
GET /api/tempmail/inbox?api_key=...&email=abc@mail.tm
"""
        msg = f"⚙️ **Project Settings**\n\n```\n{inst}\n```\n\n📊 **External Backend Usage:**\n- Files Uploaded: {ext_file_count}\n- Total Storage Used: {storage_str}\n- Auths Created: {ext_auth_count}\n- URLs Created: {ext_url_count}\n\n**Usage:**\n{usage_summary(user_info)}"
        bot.send_message(chat_id, msg, parse_mode="Markdown")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)