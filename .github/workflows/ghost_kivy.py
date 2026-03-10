#!/usr/bin/env python3
"""
ghost_kivy.py — Kivy mobile frontend for Ghost Messenger
WhatsApp-style layout optimised for touch / small screens.

Shares ALL crypto + transport backend with ghost_qt.py.
Uses the same ~/.ghost_vault.enc and ~/.ghost_history/ files,
so desktop ↔ mobile share the same contacts and history.

Install deps:
    pip install kivy httpx cryptography qrcode[pil] pillow opencv-python

Run:
    python ghost_kivy.py
    python ghost_kivy.py --offline

For Android / iOS packaging use Buildozer / kivy-ios.
buildozer.spec deps: python3, kivy, httpx, cryptography, qrcode, pillow, opencv
"""

import os
import sys
import json
import base64
import hashlib
import datetime
import argparse
import asyncio
import threading
import io
from pathlib import Path
from typing import Optional, Final

# ── Optional: silence Kivy's startup banner ──────────────────────────────────
os.environ.setdefault("KIVY_NO_ENV_CONFIG", "1")

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import httpx
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Missing deps. Run:\n  pip install httpx cryptography kivy qrcode[pil] pillow")
    sys.exit(1)

try:
    import kivy
    kivy.require("2.0.0")
    from kivy.app import App
    from kivy.clock import Clock, mainthread
    from kivy.core.window import Window
    from kivy.metrics import dp
    from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition, NoTransition
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.scrollview import ScrollView
    from kivy.uix.label import Label
    from kivy.uix.button import Button
    from kivy.uix.textinput import TextInput
    from kivy.uix.image import Image as KivyImage
    from kivy.uix.popup import Popup
    from kivy.uix.widget import Widget
    from kivy.uix.floatlayout import FloatLayout
    from kivy.graphics import Color, Rectangle, RoundedRectangle, Line
    from kivy.core.image import Image as CoreImage
    from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ObjectProperty
    from kivy.utils import get_color_from_hex
except ImportError:
    print("Missing Kivy. Run:\n  pip install kivy")
    sys.exit(1)

try:
    import qrcode
    import qrcode.image.pil
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from PIL import Image as PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ── Import shared backend ─────────────────────────────────────────────────────
# We duplicate the backend here so ghost_kivy.py is fully self-contained.
# If you keep both files in the same directory you could instead do:
#   from ghost_qt import (vault_load, vault_save, vault_init, history_load,
#                          do_send, fetch_and_decrypt, make_contact_qr_payload,
#                          parse_contact_qr_payload, generate_qr_pixmap_bytes, ...)
# For portability we inline the backend below.

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO + TRANSPORT BACKEND  (identical to ghost_qt.py)
# ══════════════════════════════════════════════════════════════════════════════

import configparser
import logging

log = logging.getLogger("ghost_kivy")

VAULT_PATH   = Path.home() / ".ghost_vault.enc"
HISTORY_DIR  = Path.home() / ".ghost_history"

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
CHAIN_VERSION  = b"ghost_chain_v1"
MAX_GAP_SEARCH = 50

_GHOST_CONFIG_PATH = Path.home() / ".ghost_config"

def _load_supabase_credentials() -> tuple[str, str]:
    url = os.environ.get("GHOST_SUPABASE_URL", "")
    key = os.environ.get("GHOST_SUPABASE_KEY", "")
    if url and key:
        return url, key
    if _GHOST_CONFIG_PATH.exists():
        cfg = configparser.ConfigParser()
        cfg.read(_GHOST_CONFIG_PATH)
        url = cfg.get("supabase", "url", fallback="")
        key = cfg.get("supabase", "key", fallback="")
        if url and key:
            return url, key
    return "", ""

SUPABASE_URL, SUPABASE_KEY = _load_supabase_credentials()
SB_TABLE = "ghost_messages"
POLL_IDLE   = 8
POLL_ACTIVE = 2

# ── Hash chain ────────────────────────────────────────────────────────────────

def chain_first_salt(secret: str) -> bytes:
    return hashlib.sha256(secret.encode() + CHAIN_VERSION).digest()

def chain_next_salt(prev: str) -> bytes:
    return hashlib.sha256(base64.urlsafe_b64decode(prev.encode())).digest()

# ── Vault ─────────────────────────────────────────────────────────────────────

def derive_vault_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())

def vault_encrypt(data: dict, password: str) -> bytes:
    salt  = os.urandom(32); nonce = os.urandom(12)
    ct    = AESGCM(derive_vault_key(password, salt)).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), None)
    return salt + nonce + ct

def vault_decrypt(raw: bytes, password: str) -> dict:
    salt, nonce, ct = raw[:32], raw[32:44], raw[44:]
    return json.loads(AESGCM(derive_vault_key(password, salt)).decrypt(nonce, ct, None).decode())

def vault_load(password: str) -> Optional[dict]:
    if not VAULT_PATH.exists(): return None
    try: return vault_decrypt(VAULT_PATH.read_bytes(), password)
    except: return None

def vault_save(data: dict, password: str):
    VAULT_PATH.write_bytes(vault_encrypt(data, password))

def vault_init(password: str) -> dict:
    data = {"my_alias": "ghost", "contacts": {}}
    vault_save(data, password); return data

# ── Message crypto ────────────────────────────────────────────────────────────

def msg_derive_key(secret: str, chain_salt: bytes) -> bytes:
    return Scrypt(salt=chain_salt, length=32, n=2**14, r=8, p=1).derive(secret.encode())

def msg_encrypt(plaintext: str, secret: str, chain_salt: bytes) -> str:
    nonce = os.urandom(12)
    ct    = AESGCM(msg_derive_key(secret, chain_salt)).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()

def msg_decrypt(blob: str, secret: str, chain_salt: bytes) -> str:
    raw   = base64.urlsafe_b64decode(blob.encode())
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(msg_derive_key(secret, chain_salt)).decrypt(nonce, ct, None).decode()

def chain_reconstruct_salt(orphan: str, secret: str, known: list) -> Optional[bytes]:
    first = chain_first_salt(secret)
    try: msg_decrypt(orphan, secret, first); return first
    except: pass
    for b in reversed(known[-MAX_GAP_SEARCH:]):
        s = chain_next_salt(b)
        try: msg_decrypt(orphan, secret, s); return s
        except: continue
    return None

# ── History ───────────────────────────────────────────────────────────────────

def _hist_key(secret: str, name: str, salt: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=f"ghost_history:{name}".encode()).derive(secret.encode())

def history_path(name: str) -> Path:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return HISTORY_DIR / f"{safe}.ghist"

def history_load(name: str, secret: str) -> dict:
    p = history_path(name)
    if not p.exists(): return {"blobs": [], "history": []}
    raw = p.read_bytes()
    if len(raw) < 28: return {"blobs": [], "history": []}
    try:
        fs, nonce, ct = raw[:16], raw[16:28], raw[28:]
        return json.loads(AESGCM(_hist_key(secret, name, fs)).decrypt(nonce, ct, None).decode())
    except: return {"blobs": [], "history": []}

def history_save(name: str, data: dict, secret: str):
    p = history_path(name); fs = os.urandom(16); nonce = os.urandom(12)
    ct = AESGCM(_hist_key(secret, name, fs)).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), None)
    p.write_bytes(fs + nonce + ct)

def history_append_blob(name: str, blob: str, secret: str) -> int:
    data = history_load(name, secret)
    if blob not in data["blobs"]: data["blobs"].append(blob); history_save(name, data, secret)
    return data["blobs"].index(blob)

def history_append_message(name: str, ts: str, text: str, idx: int, secret: str, direction: str = "in"):
    data = history_load(name, secret)
    if idx not in {e.get("blob_index") for e in data.get("history", [])}:
        data.setdefault("history", []).append({"ts": ts, "text": text, "blob_index": idx, "direction": direction})
        history_save(name, data, secret)

# ── Supabase ──────────────────────────────────────────────────────────────────

def sb_headers():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json", "Prefer": "return=representation"}

def sb_send(sender: str, recipient: str, blob: str) -> str:
    async def _go():
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(f"{SUPABASE_URL}/rest/v1/{SB_TABLE}", headers=sb_headers(),
                             json={"sender": sender, "recipient": recipient, "blob": blob})
            r.raise_for_status(); return r.json()[0]["id"]
    return asyncio.run(_go())

def sb_fetch(recipient: str, since=None, sender=None) -> list:
    async def _go():
        params = {"recipient": f"eq.{recipient}", "order": "created_at.asc"}
        if since:  params["created_at"] = f"gte.{since}"
        if sender: params["sender"]     = f"eq.{sender}"
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{SUPABASE_URL}/rest/v1/{SB_TABLE}", headers=sb_headers(), params=params)
            r.raise_for_status(); return r.json()
    return asyncio.run(_go())

def sb_delete(row_id: str):
    async def _go():
        async with httpx.AsyncClient(timeout=10) as c:
            await c.delete(f"{SUPABASE_URL}/rest/v1/{SB_TABLE}", headers=sb_headers(),
                           params={"id": f"eq.{row_id}"})
    try: asyncio.run(_go())
    except: pass

# ── Fetch + decrypt ───────────────────────────────────────────────────────────

def fetch_and_decrypt(name: str, cfg: dict, vault: dict, password: str):
    secret  = cfg.get("secret", "")
    my_alias = vault.get("my_alias", "ghost")
    if not secret: return [], vault
    fetch_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    since = cfg.get("last_fetched_at")
    sender_filter = cfg.get("recipient_alias") or None
    try: rows = sb_fetch(my_alias, since=since, sender=sender_filter)
    except Exception as e: return [{"error": str(e)}], vault

    hist_data = history_load(name, secret)
    known_blobs = hist_data.get("blobs", [])
    seen_set = set(known_blobs)
    saved_salt = cfg.get("salt_in")
    current_salt = bytes.fromhex(saved_salt) if saved_salt else (
        chain_next_salt(known_blobs[-1]) if known_blobs else chain_first_salt(secret))

    messages = []; vault_dirty = False
    for row in rows:
        blob   = row.get("blob", "") or ""
        row_id = row.get("id", "")
        ts_raw = row.get("created_at", "")
        if blob in seen_set: sb_delete(row_id); continue
        try:
            dt = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            ts = dt.strftime("%H:%M  %d %b %Y")
        except: ts = ts_raw
        blob_index = history_append_blob(name, blob, secret)
        known_blobs.append(blob); seen_set.add(blob)
        plaintext = None; chain_broken = False
        try: plaintext = msg_decrypt(blob, secret, current_salt)
        except:
            rs = chain_reconstruct_salt(blob, secret, known_blobs)
            if rs:
                try: plaintext = msg_decrypt(blob, secret, rs); current_salt = rs
                except: chain_broken = True
            else: chain_broken = True
        messages.append({"name": name, "row_id": row_id, "ts": ts, "ts_raw": ts_raw,
                          "blob": blob, "blob_index": blob_index, "plaintext": plaintext,
                          "chain_broken": chain_broken})
        if plaintext is not None:
            history_append_message(name, ts_raw, plaintext, blob_index, secret, "in")
            current_salt = chain_next_salt(blob)
            vault["contacts"][name]["salt_in"] = current_salt.hex()
            vault_dirty = True; sb_delete(row_id)
    vault["contacts"][name]["last_fetched_at"] = fetch_time
    if vault_dirty: vault_save(vault, password)
    return messages, vault

def do_send(name: str, cfg: dict, vault: dict, password: str, plaintext: str):
    secret  = cfg.get("secret", "")
    alias   = vault.get("my_alias", "ghost")
    r_alias = cfg.get("recipient_alias", name)
    saved_salt = cfg.get("salt_out")
    if saved_salt: send_salt = bytes.fromhex(saved_salt)
    else:
        hd = history_load(name, secret)
        blobs = hd.get("blobs", [])
        send_salt = chain_next_salt(blobs[-1]) if blobs else chain_first_salt(secret)
    blob = msg_encrypt(plaintext, secret, send_salt)
    try: row_id = sb_send(alias, r_alias, blob)
    except Exception as e: return None, vault, str(e)
    idx = history_append_blob(name, blob, secret)
    ts_now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    history_append_message(name, ts_now, plaintext, idx, secret, "out")
    vault["contacts"][name]["salt_out"] = chain_next_salt(blob).hex()
    vault_save(vault, password)
    return row_id, vault, None

# ── QR helpers ────────────────────────────────────────────────────────────────

QR_PREFIX = "ghost://contact?"

def make_contact_qr_payload(alias: str, secret: str) -> str:
    data = base64.urlsafe_b64encode(
        json.dumps({"alias": alias, "secret": secret}, ensure_ascii=False).encode()
    ).decode()
    return f"{QR_PREFIX}{data}"

def parse_contact_qr_payload(raw: str) -> Optional[dict]:
    if not raw.startswith(QR_PREFIX): return None
    try:
        obj = json.loads(base64.urlsafe_b64decode(raw[len(QR_PREFIX):].encode()))
        if "alias" in obj and "secret" in obj: return obj
    except: pass
    return None

def generate_qr_png_bytes(payload: str, size: int = 300) -> Optional[bytes]:
    if not HAS_QRCODE or not HAS_PIL: return None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
        qr.add_data(payload); qr.make(fit=True)
        img = qr.make_image(fill_color="#00ff41", back_color="#020402")
        img = img.resize((size, size), PILImage.LANCZOS)
        buf = io.BytesIO(); img.save(buf, format="PNG"); return buf.getvalue()
    except: return None

def kivy_texture_from_bytes(png_bytes: bytes):
    """Convert PNG bytes → Kivy CoreImage texture."""
    buf = io.BytesIO(png_bytes)
    cimg = CoreImage(buf, ext="png")
    return cimg.texture


# ══════════════════════════════════════════════════════════════════════════════
#  KIVY THEME CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

BG       = get_color_from_hex("#020402ff")
BG_DARK  = get_color_from_hex("#000000ff")
BG_MID   = get_color_from_hex("#030603ff")
GREEN    = get_color_from_hex("#00ff41ff")
GREEN_DIM= get_color_from_hex("#007a1fff")
GREEN_FG = get_color_from_hex("#b8ffcaff")
BORDER   = get_color_from_hex("#003d10ff")
SENT_BG  = get_color_from_hex("#071007ff")
ERR_RED  = get_color_from_hex("#ff2222ff")

Window.clearcolor = BG


# ══════════════════════════════════════════════════════════════════════════════
#  REUSABLE WIDGETS
# ══════════════════════════════════════════════════════════════════════════════

class GhostLabel(Label):
    def __init__(self, **kwargs):
        kwargs.setdefault("color", GREEN_FG)
        kwargs.setdefault("font_name", "RobotoMono")
        kwargs.setdefault("font_size", dp(13))
        super().__init__(**kwargs)


class GhostButton(Button):
    def __init__(self, **kwargs):
        kwargs.setdefault("color",            GREEN)
        kwargs.setdefault("background_color", BG_DARK)
        kwargs.setdefault("font_name",        "RobotoMono")
        kwargs.setdefault("font_size",        dp(13))
        kwargs.setdefault("size_hint_y",      None)
        kwargs.setdefault("height",           dp(44))
        super().__init__(**kwargs)
        self.bind(pos=self._draw, size=self._draw)

    def _draw(self, *_):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*BORDER)
            Line(rectangle=(self.x, self.y, self.width, self.height), width=1)


class GhostInput(TextInput):
    def __init__(self, **kwargs):
        kwargs.setdefault("foreground_color",    GREEN)
        kwargs.setdefault("background_color",    BG_DARK)
        kwargs.setdefault("cursor_color",        GREEN)
        kwargs.setdefault("font_name",           "RobotoMono")
        kwargs.setdefault("font_size",           dp(14))
        kwargs.setdefault("padding",             [dp(10), dp(8)])
        kwargs.setdefault("size_hint_y",         None)
        kwargs.setdefault("height",              dp(44))
        kwargs.setdefault("multiline",           False)
        super().__init__(**kwargs)


class SectionHeader(BoxLayout):
    def __init__(self, text: str, **kwargs):
        kwargs.setdefault("size_hint_y", None)
        kwargs.setdefault("height", dp(40))
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*BG_DARK)
            self._bg = Rectangle(pos=self.pos, size=self.size)
            Color(*BORDER)
            self._line = Line(points=[self.x, self.y, self.x + self.width, self.y], width=1)
        self.bind(pos=self._redraw, size=self._redraw)
        lbl = Label(text=text, color=GREEN, font_name="RobotoMono",
                    font_size=dp(14), bold=True)
        self.add_widget(lbl)

    def _redraw(self, *_):
        self._bg.pos  = self.pos; self._bg.size  = self.size
        self._line.points = [self.x, self.y, self.x + self.width, self.y]


# ══════════════════════════════════════════════════════════════════════════════
#  MESSAGE BUBBLE
# ══════════════════════════════════════════════════════════════════════════════

class MessageBubble(BoxLayout):
    def __init__(self, msg: dict, my_alias: str, contact_name: str, **kwargs):
        kwargs["orientation"] = "vertical"
        kwargs["size_hint_y"] = None
        kwargs["padding"]     = [dp(10), dp(6)]
        kwargs["spacing"]     = dp(2)
        super().__init__(**kwargs)

        direction = msg.get("direction", "in")
        is_sent   = direction == "out"
        is_broken = not msg.get("plaintext") and not is_sent
        text      = msg.get("plaintext") or msg.get("text") or "—"
        ts        = msg.get("ts", "")

        if is_broken:
            bg_color   = BG
            bar_color  = ERR_RED
            meta_color = ERR_RED
            meta_text  = f"✖ CHAIN BROKEN  {ts}"
            body_text  = "// decryption failed"
        elif is_sent:
            bg_color   = SENT_BG
            bar_color  = GREEN_DIM
            meta_color = get_color_from_hex("#1f4d2bff")
            meta_text  = f"▶ {my_alias}  {ts}"
            body_text  = text
        else:
            bg_color   = BG
            bar_color  = get_color_from_hex("#0d2615ff")
            meta_color = get_color_from_hex("#1f4d2bff")
            meta_text  = f"◀ {contact_name}  {ts}"
            body_text  = text

        with self.canvas.before:
            Color(*bg_color)
            self._bg  = Rectangle(pos=self.pos, size=self.size)
            Color(*bar_color)
            self._bar = Rectangle(pos=(self.x, self.y), size=(dp(3), self.height))

        self.bind(pos=self._redraw, size=self._redraw)

        meta_lbl = Label(
            text=meta_text, color=meta_color,
            font_name="RobotoMono", font_size=dp(11),
            size_hint_y=None, height=dp(18),
            halign="left", text_size=(None, None),
        )
        body_lbl = Label(
            text=body_text, color=GREEN_FG,
            font_name="RobotoMono", font_size=dp(13),
            size_hint_y=None, halign="left",
            text_size=(Window.width - dp(60), None),
        )
        body_lbl.bind(texture_size=lambda inst, val: setattr(inst, "height", val[1] + dp(4)))

        self.add_widget(meta_lbl)
        self.add_widget(body_lbl)

        # Calculate total height after children are added
        def _calc_height(*_):
            self.height = sum(c.height for c in self.children) + self.padding[1] * 2 + self.spacing * max(0, len(self.children) - 1)
        meta_lbl.bind(height=_calc_height)
        body_lbl.bind(height=_calc_height)

    def _redraw(self, *_):
        self._bg.pos  = self.pos; self._bg.size  = self.size
        self._bar.pos = (self.x, self.y); self._bar.size = (dp(3), self.height)


# ══════════════════════════════════════════════════════════════════════════════
#  SCREENS
# ══════════════════════════════════════════════════════════════════════════════

# ── Unlock Screen ─────────────────────────────────────────────────────────────

class UnlockScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="unlock", **kwargs)
        self._app = app
        self._is_new = not VAULT_PATH.exists()
        self._weak_warned = False
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical", padding=dp(24), spacing=dp(10))
        root.add_widget(Widget(size_hint_y=None, height=dp(20)))

        logo = Label(
            text="[b][color=#00ff41]GHOST[/color][/b]",
            markup=True, font_size=dp(32),
            size_hint_y=None, height=dp(50),
        )
        root.add_widget(logo)

        tagline = Label(
            text="end-to-end encrypted · supabase · hash chain",
            color=get_color_from_hex("#1f4d2bff"),
            font_size=dp(11), size_hint_y=None, height=dp(24),
        )
        root.add_widget(tagline)
        root.add_widget(Widget(size_hint_y=None, height=dp(10)))

        if self._is_new:
            root.add_widget(Label(text="// NEW VAULT — choose a strong master password",
                                  color=GREEN_DIM, font_size=dp(12), size_hint_y=None, height=dp(24)))
            self.pw1_input    = GhostInput(hint_text="Master password",    password=True)
            self.pw2_input    = GhostInput(hint_text="Confirm password",   password=True)
            self.alias_input  = GhostInput(hint_text="Your alias (e.g. alice)")
            root.add_widget(self.pw1_input)
            root.add_widget(self.pw2_input)
            root.add_widget(self.alias_input)
            btn_text = "[ INITIALIZE VAULT ]"
        else:
            root.add_widget(Label(text="// VAULT FOUND — authenticate to continue",
                                  color=GREEN_DIM, font_size=dp(12), size_hint_y=None, height=dp(24)))
            self.pw1_input   = GhostInput(hint_text="Master password", password=True)
            root.add_widget(self.pw1_input)
            btn_text = "[ DECRYPT & ENTER ]"

        self.error_lbl = Label(text="", color=ERR_RED, font_size=dp(12),
                               size_hint_y=None, height=dp(24))
        root.add_widget(self.error_lbl)

        btn = GhostButton(text=btn_text)
        btn.bind(on_press=self._do_unlock)
        root.add_widget(btn)

        root.add_widget(Widget())  # filler
        self.add_widget(root)

    def _do_unlock(self, *_):
        pw1 = self.pw1_input.text
        if self._is_new:
            pw2   = self.pw2_input.text
            alias = self.alias_input.text.strip() or "ghost"
            if not pw1:
                self.error_lbl.text = "Password cannot be empty."; return
            if pw1 != pw2:
                self.error_lbl.text = "Passwords don't match."; return
            if len(pw1) < 12 and not self._weak_warned:
                self._weak_warned = True
                self.error_lbl.text = "⚠ Password < 12 chars. Tap again to proceed."; return
            self._weak_warned = False
            vault = vault_init(pw1); vault["my_alias"] = alias; vault_save(vault, pw1)
            self._app.on_unlocked(vault, pw1)
        else:
            vault = vault_load(pw1)
            if vault is None:
                self.error_lbl.text = "Wrong password. Try again."; self.pw1_input.text = ""; return
            self._app.on_unlocked(vault, pw1)


# ── Contacts Screen ───────────────────────────────────────────────────────────

class ContactsScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="contacts", **kwargs)
        self._app = app
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical")

        # Header
        header = SectionHeader("GHOST  ·  contacts")
        root.add_widget(header)

        # Contact list scroll area
        self.scroll = ScrollView(size_hint=(1, 1))
        self.contacts_layout = BoxLayout(orientation="vertical", size_hint_y=None, spacing=1)
        self.contacts_layout.bind(minimum_height=self.contacts_layout.setter("height"))
        self.scroll.add_widget(self.contacts_layout)
        root.add_widget(self.scroll)

        # Bottom button bar
        btn_bar = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(50), spacing=1)
        btn_add     = GhostButton(text="[+] Add",     height=dp(50))
        btn_scan_qr = GhostButton(text="[⬛] Scan QR", height=dp(50))
        btn_share   = GhostButton(text="[QR] Share",  height=dp(50))
        btn_settings= GhostButton(text="[~] Settings",height=dp(50))
        btn_add.bind(on_press=lambda _: self._app.sm.switch_to_screen("add_contact"))
        btn_scan_qr.bind(on_press=lambda _: self._app.sm.switch_to_screen("scan_qr"))
        btn_share.bind(on_press=self._show_my_qr)
        btn_settings.bind(on_press=lambda _: self._app.sm.switch_to_screen("settings"))
        for b in [btn_add, btn_scan_qr, btn_share, btn_settings]:
            btn_bar.add_widget(b)
        root.add_widget(btn_bar)

        self.add_widget(root)

    def refresh(self):
        self.contacts_layout.clear_widgets()
        vault = self._app.vault
        if not vault:
            return
        contacts = vault.get("contacts", {})
        if not contacts:
            lbl = Label(text="// No contacts yet. Add one.",
                        color=GREEN_DIM, font_size=dp(13),
                        size_hint_y=None, height=dp(60))
            self.contacts_layout.add_widget(lbl)
            return
        for name, cfg in contacts.items():
            unread = self._app.unread.get(name, 0)
            unread_str = f"  ● {unread}" if unread else ""
            row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(64), padding=[dp(12), dp(6)])
            with row.canvas.before:
                Color(*BG_MID)
                Rectangle(pos=row.pos, size=row.size)
                Color(*BORDER)
                Line(points=[row.x, row.y, row.x + row.width, row.y], width=1)
            row.bind(pos=lambda inst, *_: inst.canvas.before.clear() or self._redraw_row(inst),
                     size=lambda inst, *_: self._redraw_row(inst))

            info = BoxLayout(orientation="vertical", spacing=dp(2))
            name_lbl  = Label(text=f"[b]{name}[/b]{unread_str}", markup=True, color=GREEN_FG,
                              font_size=dp(14), halign="left", valign="middle",
                              size_hint_y=None, height=dp(28), text_size=(Window.width * 0.7, None))
            alias_lbl = Label(text=f"→ {cfg.get('recipient_alias', '')}",
                              color=get_color_from_hex("#1f4d2bff"), font_size=dp(11),
                              halign="left", size_hint_y=None, height=dp(20),
                              text_size=(Window.width * 0.7, None))
            info.add_widget(name_lbl); info.add_widget(alias_lbl)
            row.add_widget(info)

            chat_btn = GhostButton(text="Chat ▶", size_hint_x=None, width=dp(80), height=dp(44))
            _name = name  # closure capture
            chat_btn.bind(on_press=lambda _, n=_name: self._app.open_chat(n))
            row.add_widget(chat_btn)
            self.contacts_layout.add_widget(row)

    def _redraw_row(self, row):
        row.canvas.before.clear()
        with row.canvas.before:
            Color(*BG_MID)
            Rectangle(pos=row.pos, size=row.size)
            Color(*BORDER)
            Line(points=[row.x, row.y, row.x + row.width, row.y], width=1)

    def _show_my_qr(self, *_):
        if not self._app.active_contact:
            self._app.sm.switch_to_screen("contacts")
            self._show_popup("Select a contact first, then tap Share QR.", error=True)
            return
        vault = self._app.vault
        name = self._app.active_contact
        secret = vault.get("contacts", {}).get(name, {}).get("secret", "")
        alias  = vault.get("my_alias", "ghost")
        self._app.sm.get_screen("show_qr").set_qr(alias, secret, name)
        self._app.sm.switch_to_screen("show_qr")

    def _show_popup(self, msg: str, error=False):
        color = ERR_RED if error else GREEN
        lbl   = Label(text=msg, color=color, font_size=dp(13))
        popup = Popup(title="Ghost", content=lbl, size_hint=(0.8, 0.3))
        popup.open()


# ── Chat Screen ───────────────────────────────────────────────────────────────

class ChatScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="chat", **kwargs)
        self._app = app
        self._poll_event = None
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical")

        # Header
        self.header_bar = BoxLayout(orientation="horizontal", size_hint_y=None,
                                    height=dp(52), padding=[dp(8), dp(6)], spacing=dp(6))
        with self.header_bar.canvas.before:
            Color(*BG_DARK)
            self._hbg = Rectangle(pos=self.header_bar.pos, size=self.header_bar.size)
        self.header_bar.bind(pos=self._redraw_header, size=self._redraw_header)

        back_btn = GhostButton(text="◀ Back", size_hint_x=None, width=dp(80), height=dp(40))
        back_btn.bind(on_press=self._go_back)
        self.contact_lbl = Label(text="", color=GREEN, font_name="RobotoMono",
                                 font_size=dp(14), bold=True, halign="left",
                                 text_size=(None, None))
        sync_btn = GhostButton(text="↻", size_hint_x=None, width=dp(44), height=dp(40))
        sync_btn.bind(on_press=self._do_sync)
        self.header_bar.add_widget(back_btn)
        self.header_bar.add_widget(self.contact_lbl)
        self.header_bar.add_widget(sync_btn)
        root.add_widget(self.header_bar)

        # Messages scroll
        self.scroll = ScrollView(size_hint=(1, 1), do_scroll_x=False)
        self.msg_layout = BoxLayout(orientation="vertical", size_hint_y=None,
                                    spacing=dp(2), padding=[0, dp(6)])
        self.msg_layout.bind(minimum_height=self.msg_layout.setter("height"))
        self.scroll.add_widget(self.msg_layout)
        root.add_widget(self.scroll)

        # Compose bar
        compose = BoxLayout(orientation="horizontal", size_hint_y=None,
                            height=dp(52), padding=[dp(6), dp(4)], spacing=dp(6))
        with compose.canvas.before:
            Color(*BG_DARK)
            Rectangle(pos=compose.pos, size=compose.size)
        self.compose_input = GhostInput(hint_text="Type a message…", multiline=False,
                                        height=dp(42), size_hint_y=None)
        send_btn = GhostButton(text="SEND", size_hint_x=None, width=dp(80), height=dp(42))
        send_btn.bind(on_press=self._do_send)
        compose.add_widget(self.compose_input)
        compose.add_widget(send_btn)
        root.add_widget(compose)

        # Status
        self.status_lbl = Label(text="", color=GREEN_DIM, font_size=dp(11),
                                 size_hint_y=None, height=dp(22))
        root.add_widget(self.status_lbl)

        self.add_widget(root)

    def _redraw_header(self, *_):
        self._hbg.pos  = self.header_bar.pos
        self._hbg.size = self.header_bar.size

    def load_contact(self, name: str):
        self.contact_lbl.text = name
        self._load_conversation(name)
        self._start_auto_sync()

    def _load_conversation(self, name: str):
        vault  = self._app.vault
        secret = vault.get("contacts", {}).get(name, {}).get("secret", "")
        hist   = history_load(name, secret)
        msgs   = hist.get("history", [])

        self.msg_layout.clear_widgets()
        my_alias = vault.get("my_alias", "ghost")
        for msg in msgs:
            bubble = MessageBubble(msg, my_alias, name)
            self.msg_layout.add_widget(bubble)
        Clock.schedule_once(lambda _: self._scroll_bottom(), 0.1)

    def _scroll_bottom(self):
        self.scroll.scroll_y = 0

    def _go_back(self, *_):
        self._stop_auto_sync()
        self._app.sm.switch_to_screen("contacts")
        self._app.screen_contacts.refresh()

    def _do_send(self, *_):
        text = self.compose_input.text.strip()
        if not text or not self._app.active_contact: return
        self.compose_input.text = ""
        self.status_lbl.text    = "Sending…"
        self.status_lbl.color   = get_color_from_hex("#ffb300ff")
        name = self._app.active_contact
        cfg  = self._app.vault.get("contacts", {}).get(name, {})

        def _worker():
            result = do_send(name, cfg, self._app.vault, self._app.password, text)
            Clock.schedule_once(lambda _: self._on_send_done(name, text, result), 0)

        threading.Thread(target=_worker, daemon=True).start()

    @mainthread
    def _on_send_done(self, name, text, result):
        row_id, vault, error = result if not isinstance(result, dict) else (None, self._app.vault, result.get("__error__", "Unknown error"))
        if error:
            self.status_lbl.text  = f"✗ Send failed: {error}"
            self.status_lbl.color = ERR_RED
            return
        self._app.vault = vault
        self.status_lbl.text  = "✓ Sent"
        self.status_lbl.color = GREEN
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M  %d %b %Y")
        bubble = MessageBubble({"direction": "out", "plaintext": text, "text": text, "ts": ts},
                               vault.get("my_alias", "ghost"), name)
        self.msg_layout.add_widget(bubble)
        Clock.schedule_once(lambda _: self._scroll_bottom(), 0.05)

    def _do_sync(self, *_):
        name = self._app.active_contact
        if not name: return
        self.status_lbl.text  = "Syncing…"
        self.status_lbl.color = get_color_from_hex("#ffb300ff")
        cfg = self._app.vault.get("contacts", {}).get(name, {})

        def _worker():
            msgs, vault = fetch_and_decrypt(name, cfg, self._app.vault, self._app.password)
            Clock.schedule_once(lambda _: self._on_sync_done(name, msgs, vault), 0)

        threading.Thread(target=_worker, daemon=True).start()

    @mainthread
    def _on_sync_done(self, name, messages, vault):
        self._app.vault = vault
        new = [m for m in messages if m.get("plaintext")]
        if new:
            self.status_lbl.text  = f"✓ {len(new)} new message(s)"
            self.status_lbl.color = GREEN
            self._load_conversation(name)
        else:
            errs = [m for m in messages if "error" in m]
            if errs:
                self.status_lbl.text  = f"✗ {errs[0]['error']}"
                self.status_lbl.color = ERR_RED
            else:
                self.status_lbl.text  = "No new messages."
                self.status_lbl.color = GREEN_DIM

    def _start_auto_sync(self):
        self._stop_auto_sync()
        self._poll_event = Clock.schedule_interval(lambda _: self._do_sync(), POLL_IDLE)

    def _stop_auto_sync(self):
        if self._poll_event:
            self._poll_event.cancel()
            self._poll_event = None


# ── Add Contact Screen ────────────────────────────────────────────────────────

class AddContactScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="add_contact", **kwargs)
        self._app = app
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical", padding=dp(20), spacing=dp(10))
        root.add_widget(SectionHeader("ADD CONTACT"))

        root.add_widget(Label(text="Contact name:", color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24), halign="left", text_size=(None, None)))
        self.name_input = GhostInput(hint_text="e.g. Alice")
        root.add_widget(self.name_input)

        root.add_widget(Label(text="Their Supabase alias:", color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24), halign="left", text_size=(None, None)))
        self.alias_input = GhostInput(hint_text="e.g. alice")
        root.add_widget(self.alias_input)

        root.add_widget(Label(text="Shared secret:", color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24), halign="left", text_size=(None, None)))
        self.secret_input = GhostInput(hint_text="Shared passphrase", password=True)
        root.add_widget(self.secret_input)

        self.error_lbl = Label(text="", color=ERR_RED, font_size=dp(12),
                               size_hint_y=None, height=dp(24))
        root.add_widget(self.error_lbl)

        btn_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(48), spacing=dp(8))
        cancel_btn = GhostButton(text="Cancel")
        add_btn    = GhostButton(text="Add Contact")
        cancel_btn.bind(on_press=self._cancel)
        add_btn.bind(on_press=self._add)
        btn_row.add_widget(cancel_btn); btn_row.add_widget(add_btn)
        root.add_widget(btn_row)

        root.add_widget(Widget())
        self.add_widget(root)

    def on_pre_enter(self, *_):
        self.name_input.text = ""; self.alias_input.text = ""; self.secret_input.text = ""
        self.error_lbl.text  = ""

    def _cancel(self, *_):
        self._app.sm.switch_to_screen("contacts")

    def _add(self, *_):
        name   = self.name_input.text.strip()
        calias = self.alias_input.text.strip()
        secret = self.secret_input.text.strip()
        if not all([name, calias, secret]):
            self.error_lbl.text = "All fields are required."; return
        self._app.vault.setdefault("contacts", {})[name] = {
            "recipient_alias": calias, "secret": secret
        }
        vault_save(self._app.vault, self._app.password)
        self._app.sm.switch_to_screen("contacts")
        self._app.screen_contacts.refresh()


# ── Show QR Screen ────────────────────────────────────────────────────────────

class ShowQRScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="show_qr", **kwargs)
        self._app = app
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
        root.add_widget(SectionHeader("SHARE QR CODE"))

        self.info_lbl = Label(
            text="Scan this code to add me as a contact.",
            color=GREEN_DIM, font_size=dp(12),
            size_hint_y=None, height=dp(36),
            halign="center", text_size=(Window.width - dp(32), None),
        )
        root.add_widget(self.info_lbl)

        self.qr_image = KivyImage(size_hint=(1, 1), allow_stretch=True, keep_ratio=True)
        root.add_widget(self.qr_image)

        self.qr_status = Label(text="", color=GREEN_DIM, font_size=dp(11),
                               size_hint_y=None, height=dp(24))
        root.add_widget(self.qr_status)

        # Raw payload (scrollable)
        self.payload_input = GhostInput(hint_text="payload", height=dp(40))
        self.payload_input.readonly = True
        self.payload_input.foreground_color = get_color_from_hex("#007a1fff")
        root.add_widget(self.payload_input)

        back_btn = GhostButton(text="◀ Back")
        back_btn.bind(on_press=lambda _: self._app.sm.switch_to_screen("contacts"))
        root.add_widget(back_btn)

        self.add_widget(root)

    def set_qr(self, alias: str, secret: str, contact_name: str):
        payload = make_contact_qr_payload(alias, secret)
        self.payload_input.text = payload
        self.info_lbl.text = f"Scanning this code will add\nyou ({alias}) to {contact_name}'s contacts."

        if HAS_QRCODE and HAS_PIL:
            png = generate_qr_png_bytes(payload, 400)
            if png:
                texture = kivy_texture_from_bytes(png)
                self.qr_image.texture = texture
                self.qr_status.text   = ""
                return
        self.qr_status.text  = "Install qrcode + pillow for QR image."
        self.qr_status.color = get_color_from_hex("#ffb300ff")


# ── Scan QR Screen ────────────────────────────────────────────────────────────

class ScanQRScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="scan_qr", **kwargs)
        self._app = app
        self._scanner_thread = None
        self._scanning = False
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical", padding=dp(16), spacing=dp(10))
        root.add_widget(SectionHeader("SCAN QR CODE"))

        self.cam_image = KivyImage(size_hint=(1, 0.55), allow_stretch=True, keep_ratio=True)
        root.add_widget(self.cam_image)

        self.status_lbl = Label(text="Press Start Camera to scan.",
                                color=GREEN_DIM, font_size=dp(12),
                                size_hint_y=None, height=dp(28))
        root.add_widget(self.status_lbl)

        # Contact name input
        root.add_widget(Label(text="Contact name for this person:",
                              color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24)))
        self.name_input = GhostInput(hint_text="e.g. Alice")
        root.add_widget(self.name_input)

        btn_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(48), spacing=dp(8))
        self.btn_start = GhostButton(text="▶ Start Camera")
        self.btn_stop  = GhostButton(text="■ Stop")
        back_btn       = GhostButton(text="◀ Back")
        self.btn_start.bind(on_press=self._start_scan)
        self.btn_stop.bind(on_press=self._stop_scan)
        back_btn.bind(on_press=self._go_back)
        btn_row.add_widget(self.btn_start); btn_row.add_widget(self.btn_stop)
        root.add_widget(btn_row)
        root.add_widget(back_btn)

        self.add_widget(root)

    def _go_back(self, *_):
        self._stop_scan()
        self._app.sm.switch_to_screen("contacts")

    def _start_scan(self, *_):
        if not HAS_CV2:
            self.status_lbl.text  = "opencv-python not installed."
            self.status_lbl.color = ERR_RED
            return
        self._scanning = True
        self.btn_start.disabled = True

        def _worker():
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                Clock.schedule_once(lambda _: setattr(self.status_lbl, "text", "Cannot open camera."), 0)
                return
            detector = cv2.QRCodeDetector()
            while self._scanning:
                ret, frame = cap.read()
                if not ret: continue
                # Display frame
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                h, w, _ = rgb.shape
                buf = rgb.tobytes()
                texture = None
                from kivy.graphics.texture import Texture as KTexture
                texture = KTexture.create(size=(w, h), colorfmt="rgb")
                texture.blit_buffer(buf, colorfmt="rgb", bufferfmt="ubyte")
                texture.flip_vertical()
                Clock.schedule_once(lambda _, t=texture: setattr(self.cam_image, "texture", t), 0)
                # Scan
                data, _, _ = detector.detectAndDecode(frame)
                if data:
                    cap.release()
                    self._scanning = False
                    Clock.schedule_once(lambda _, d=data: self._on_found(d), 0)
                    return
            cap.release()

        self._scanner_thread = threading.Thread(target=_worker, daemon=True)
        self._scanner_thread.start()

    def _stop_scan(self, *_):
        self._scanning = False
        self.btn_start.disabled = False
        self.status_lbl.text  = "Stopped."
        self.status_lbl.color = GREEN_DIM

    def _on_found(self, data: str):
        self._stop_scan()
        obj = parse_contact_qr_payload(data)
        if not obj:
            self.status_lbl.text  = "✗ Not a valid Ghost QR code."
            self.status_lbl.color = ERR_RED
            return
        name = self.name_input.text.strip()
        if not name:
            self.status_lbl.text  = f"✓ Scanned {obj['alias']}. Enter a contact name and confirm."
            self.status_lbl.color = GREEN
            # Pre-fill a suggested name from the alias
            self.name_input.text = obj["alias"].capitalize()
            self._pending_scan = obj
            return
        self._save_scanned(name, obj)

    def _save_scanned(self, name: str, obj: dict):
        self._app.vault.setdefault("contacts", {})[name] = {
            "recipient_alias": obj["alias"],
            "secret":          obj["secret"],
        }
        vault_save(self._app.vault, self._app.password)
        self.status_lbl.text  = f"✓ Contact '{name}' added!"
        self.status_lbl.color = GREEN
        Clock.schedule_once(lambda _: self._finish(), 1.5)

    def _finish(self):
        self._app.sm.switch_to_screen("contacts")
        self._app.screen_contacts.refresh()

    def on_pre_enter(self, *_):
        self.name_input.text = ""; self.status_lbl.text = "Press Start Camera to scan."
        self.status_lbl.color = GREEN_DIM
        self._scanning = False; self.btn_start.disabled = False


# ── Settings Screen ───────────────────────────────────────────────────────────

class SettingsScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(name="settings", **kwargs)
        self._app = app
        self._build()

    def _build(self):
        root = BoxLayout(orientation="vertical", padding=dp(20), spacing=dp(10))
        root.add_widget(SectionHeader("SETTINGS"))

        root.add_widget(Label(text="Your alias:", color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24), halign="left", text_size=(None, None)))
        self.alias_input = GhostInput(hint_text="Your alias")
        root.add_widget(self.alias_input)

        root.add_widget(Label(text="Change master password:", color=GREEN_DIM, font_size=dp(12),
                              size_hint_y=None, height=dp(24), halign="left", text_size=(None, None)))
        self.pw_current = GhostInput(hint_text="Current password", password=True)
        self.pw_new     = GhostInput(hint_text="New password",     password=True)
        self.pw_confirm = GhostInput(hint_text="Confirm new password", password=True)
        root.add_widget(self.pw_current); root.add_widget(self.pw_new); root.add_widget(self.pw_confirm)

        self.status_lbl = Label(text="", color=GREEN, font_size=dp(12),
                                size_hint_y=None, height=dp(24))
        root.add_widget(self.status_lbl)

        btn_row = BoxLayout(orientation="horizontal", size_hint_y=None, height=dp(48), spacing=dp(8))
        save_btn   = GhostButton(text="Save")
        cancel_btn = GhostButton(text="Back")
        save_btn.bind(on_press=self._save)
        cancel_btn.bind(on_press=lambda _: self._app.sm.switch_to_screen("contacts"))
        btn_row.add_widget(save_btn); btn_row.add_widget(cancel_btn)
        root.add_widget(btn_row)

        vault_info = Label(
            text=f"Vault: {VAULT_PATH}\nHistory: {HISTORY_DIR}",
            color=get_color_from_hex("#1f4d2bff"), font_size=dp(10),
            size_hint_y=None, height=dp(48),
        )
        root.add_widget(vault_info)
        root.add_widget(Widget())
        self.add_widget(root)

    def on_pre_enter(self, *_):
        vault = self._app.vault
        self.alias_input.text = vault.get("my_alias", "ghost") if vault else ""
        self.pw_current.text = self.pw_new.text = self.pw_confirm.text = ""
        self.status_lbl.text = ""

    def _save(self, *_):
        self.status_lbl.color = GREEN
        alias = self.alias_input.text.strip()
        if alias and self._app.vault:
            self._app.vault["my_alias"] = alias
            vault_save(self._app.vault, self._app.password)

        pc = self.pw_current.text; pn = self.pw_new.text; pcnf = self.pw_confirm.text
        if pc or pn or pcnf:
            if vault_load(pc) is None:
                self.status_lbl.text = "✗ Current password is wrong."; self.status_lbl.color = ERR_RED; return
            if pn != pcnf:
                self.status_lbl.text = "✗ New passwords don't match."; self.status_lbl.color = ERR_RED; return
            if not pn:
                self.status_lbl.text = "✗ New password cannot be empty."; self.status_lbl.color = ERR_RED; return
            vault_save(self._app.vault, pn)
            self._app.password = pn
            self.status_lbl.text = "✓ Password changed."
        else:
            self.status_lbl.text = "✓ Settings saved."


# ══════════════════════════════════════════════════════════════════════════════
#  SCREEN MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class GhostScreenManager(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.transition = SlideTransition()

    def switch_to_screen(self, name: str, direction: str = "left"):
        self.transition.direction = direction
        self.current = name


# ══════════════════════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════════════════════

class GhostApp(App):
    vault:          Optional[dict] = None
    password:       str = ""
    active_contact: Optional[str] = None
    unread:         dict = {}
    offline:        bool = False

    def build(self):
        Window.softinput_mode = "below_target"  # keyboard pushes layout up on mobile

        self.sm = GhostScreenManager()

        # Create all screens
        unlock_screen   = UnlockScreen(self)
        self.screen_contacts = ContactsScreen(self)
        self.screen_chat     = ChatScreen(self)
        self.screen_add      = AddContactScreen(self)
        self.screen_show_qr  = ShowQRScreen(self)
        self.screen_scan_qr  = ScanQRScreen(self)
        self.screen_settings = SettingsScreen(self)

        for s in [unlock_screen, self.screen_contacts, self.screen_chat,
                  self.screen_add, self.screen_show_qr, self.screen_scan_qr,
                  self.screen_settings]:
            self.sm.add_widget(s)

        self.sm.current = "unlock"
        return self.sm

    def on_unlocked(self, vault: dict, password: str):
        self.vault    = vault
        self.password = password
        self.screen_contacts.refresh()
        self.sm.switch_to_screen("contacts")

    def open_chat(self, name: str):
        self.active_contact     = name
        self.unread[name]       = 0
        self.screen_contacts.refresh()
        self.screen_chat.load_contact(name)
        self.sm.switch_to_screen("chat")

    def get_application_name(self):
        return "Ghost Messenger"


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ghost kivy — encrypted messaging")
    parser.add_argument("--offline", action="store_true", default=False)
    args, _ = parser.parse_known_args()

    app = GhostApp()
    app.offline = args.offline
    app.run()


if __name__ == "__main__":
    main()
