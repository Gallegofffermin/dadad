#!/usr/bin/env python3
"""
ghost_qt.py — PyQt6 GUI frontend for Ghost Messenger (Supabase edition)

All crypto, transport, history, and polling backend code is identical to
ghost-3-2.py.  Only the frontend has changed: Textual TUI → PyQt6 GUI.

The layout is WhatsApp-inspired:
  ┌──────────────┬────────────────────────────────────┐
  │  Sidebar     │  Chat header                       │
  │  ──────────  │  ──────────────────────────────    │
  │  Contacts    │  Message list (scrollable)         │
  │              │  ──────────────────────────────    │
  │  [+] Add     │  [ compose input        ] [SEND]   │
  │  [~] Settings│  Status bar                        │
  └──────────────┴────────────────────────────────────┘

Install deps:
    pip install PyQt6 httpx cryptography

Run:
    python ghost_qt.py
    python ghost_qt.py --offline
"""

import os
import sys
import json
import base64
import hashlib
import datetime
import argparse
import asyncio
import secrets
import configparser
import multiprocessing
import queue
import logging
import threading
from pathlib import Path
from typing import Optional, Final

log = logging.getLogger("ghost")

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import httpx
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Missing dependencies. Run:\n  pip install httpx cryptography PyQt6")
    sys.exit(1)

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QDialog,
        QVBoxLayout, QHBoxLayout, QSplitter,
        QListWidget, QListWidgetItem, QScrollArea,
        QLineEdit, QPushButton, QLabel, QFrame,
        QDialogButtonBox, QMessageBox, QSizePolicy,
        QStackedWidget, QTextEdit, QCheckBox,
    )
    from PyQt6.QtCore import (
        Qt, QTimer, QThread, pyqtSignal, QObject, QSize,
        QPropertyAnimation, QEasingCurve,
    )
    from PyQt6.QtGui import (
        QFont, QColor, QPalette, QIcon, QPixmap,
        QTextCursor, QKeySequence, QShortcut,
    )
except ImportError:
    print("Missing PyQt6. Run:\n  pip install PyQt6")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO BACKEND  (unchanged from ghost-3-2.py)
# ══════════════════════════════════════════════════════════════════════════════

VAULT_PATH   = Path.home() / ".ghost_vault.enc"
HISTORY_DIR  = Path.home() / ".ghost_history"

SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1

CHAIN_VERSION  = b"ghost_chain_v1"
MAX_GAP_SEARCH = 50

# ── Supabase config ────────────────────────────────────────────────────────────
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

    _HARDCODED_URL = ""
    _HARDCODED_KEY = ""
    if _HARDCODED_URL and _HARDCODED_KEY:
        print(
            "\033[33m[ghost] WARNING: Using hardcoded Supabase credentials.\033[0m",
            file=sys.stderr
        )
        return _HARDCODED_URL, _HARDCODED_KEY

    return "", ""

SUPABASE_URL: Final[str]
SUPABASE_KEY: Final[str]
SUPABASE_URL, SUPABASE_KEY = _load_supabase_credentials()

SB_TABLE: Final[str] = "ghost_messages"

POLL_ACTIVE    = 2
POLL_IDLE      = 8
ACTIVE_TIMEOUT = 45


# ── Hash chain ────────────────────────────────────────────────────────────────

def chain_first_salt(secret: str) -> bytes:
    return hashlib.sha256(secret.encode() + CHAIN_VERSION).digest()

def chain_next_salt(prev_ciphertext_b64: str) -> bytes:
    raw = base64.urlsafe_b64decode(prev_ciphertext_b64.encode())
    return hashlib.sha256(raw).digest()


# ── Vault crypto ──────────────────────────────────────────────────────────────

def derive_vault_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode())

def vault_encrypt(data: dict, password: str) -> bytes:
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = derive_vault_key(password, salt)
    ct    = AESGCM(key).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), None)
    return salt + nonce + ct

def vault_decrypt(raw: bytes, password: str) -> dict:
    salt, nonce, ct = raw[:32], raw[32:44], raw[44:]
    key = derive_vault_key(password, salt)
    return json.loads(AESGCM(key).decrypt(nonce, ct, None).decode())

def vault_load(password: str) -> Optional[dict]:
    if not VAULT_PATH.exists():
        return None
    try:
        return vault_decrypt(VAULT_PATH.read_bytes(), password)
    except Exception as exc:
        log.warning("vault_load: decryption failed (%s)", exc)
        return None

def vault_save(data: dict, password: str):
    enc = vault_encrypt(data, password)
    VAULT_PATH.write_bytes(enc)

def vault_init(password: str) -> dict:
    data = {"my_alias": "ghost", "contacts": {}}
    vault_save(data, password)
    return data


# ── Message crypto ────────────────────────────────────────────────────────────

def msg_derive_key(secret: str, chain_salt: bytes) -> bytes:
    kdf = Scrypt(salt=chain_salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(secret.encode())

def msg_encrypt(plaintext: str, secret: str, chain_salt: bytes) -> str:
    key   = msg_derive_key(secret, chain_salt)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()

def msg_decrypt(blob: str, secret: str, chain_salt: bytes) -> str:
    key   = msg_derive_key(secret, chain_salt)
    raw   = base64.urlsafe_b64decode(blob.encode())
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()


# ── Chain reconstruction ──────────────────────────────────────────────────────

def chain_reconstruct_salt(orphan_blob: str, secret: str, known_blobs: list) -> Optional[bytes]:
    first_salt = chain_first_salt(secret)
    try:
        msg_decrypt(orphan_blob, secret, first_salt)
        return first_salt
    except Exception:
        pass
    for candidate_blob in reversed(known_blobs[-MAX_GAP_SEARCH:]):
        candidate_salt = chain_next_salt(candidate_blob)
        try:
            msg_decrypt(orphan_blob, secret, candidate_salt)
            return candidate_salt
        except Exception:
            continue
    return None


# ── Local history ─────────────────────────────────────────────────────────────

def history_path(contact_name: str) -> Path:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in contact_name)
    return HISTORY_DIR / f"{safe}.ghist"

def _history_derive_key(secret: str, contact_name: str, salt: bytes) -> bytes:
    info = f"ghost_history:{contact_name}".encode()
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=info).derive(secret.encode())

def history_load(contact_name: str, secret: str) -> dict:
    p = history_path(contact_name)
    if not p.exists():
        legacy = p.with_suffix(".json")
        if legacy.exists():
            try:
                data = json.loads(legacy.read_text(encoding="utf-8"))
                history_save(contact_name, data, secret)
                legacy.unlink()
                return data
            except Exception:
                pass
        return {"blobs": [], "history": []}
    raw = p.read_bytes()
    if len(raw) < 28:
        return {"blobs": [], "history": []}
    try:
        file_salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = _history_derive_key(secret, contact_name, file_salt)
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        log.warning("history_load(%s): decryption failed (%s)", contact_name, exc)
        return {"blobs": [], "history": []}

def history_save(contact_name: str, data: dict, secret: str):
    p = history_path(contact_name)
    file_salt = os.urandom(16)
    nonce     = os.urandom(12)
    key       = _history_derive_key(secret, contact_name, file_salt)
    payload   = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ct        = AESGCM(key).encrypt(nonce, payload, None)
    p.write_bytes(file_salt + nonce + ct)

def history_append_blob(contact_name: str, blob: str, secret: str) -> int:
    data = history_load(contact_name, secret)
    if blob not in data["blobs"]:
        data["blobs"].append(blob)
        history_save(contact_name, data, secret)
    return data["blobs"].index(blob)

def history_append_message(contact_name: str, ts: str, text: str, blob_index: int, secret: str, direction: str = "in"):
    data = history_load(contact_name, secret)
    existing = {e.get("blob_index") for e in data.get("history", [])}
    if blob_index not in existing:
        data.setdefault("history", []).append({
            "ts": ts, "text": text, "blob_index": blob_index, "direction": direction
        })
        history_save(contact_name, data, secret)


# ── Supabase transport ────────────────────────────────────────────────────────

def sb_headers() -> dict:
    return {
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type":  "application/json",
        "Prefer":        "return=representation",
    }

async def sb_send_async(sender_alias: str, recipient_alias: str, blob: str) -> str:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"{SUPABASE_URL}/rest/v1/{SB_TABLE}",
            headers=sb_headers(),
            json={"sender": sender_alias, "recipient": recipient_alias, "blob": blob},
        )
        r.raise_for_status()
        return r.json()[0]["id"]

async def sb_fetch_async(recipient_alias: str, since: Optional[str] = None, sender_alias: Optional[str] = None) -> list:
    params: dict = {"recipient": f"eq.{recipient_alias}", "order": "created_at.asc"}
    if since:
        params["created_at"] = f"gte.{since}"
    if sender_alias:
        params["sender"] = f"eq.{sender_alias}"
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            f"{SUPABASE_URL}/rest/v1/{SB_TABLE}",
            headers=sb_headers(),
            params=params,
        )
        r.raise_for_status()
        return r.json()

async def sb_delete_async(row_id: str):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.delete(
                f"{SUPABASE_URL}/rest/v1/{SB_TABLE}",
                headers=sb_headers(),
                params={"id": f"eq.{row_id}"},
            )
    except Exception:
        pass

def sb_send(sender_alias: str, recipient_alias: str, blob: str) -> str:
    return asyncio.run(sb_send_async(sender_alias, recipient_alias, blob))

def sb_fetch(recipient_alias: str, since: Optional[str] = None, sender_alias: Optional[str] = None) -> list:
    return asyncio.run(sb_fetch_async(recipient_alias, since=since, sender_alias=sender_alias))

def sb_delete(row_id: str):
    asyncio.run(sb_delete_async(row_id))


# ── Message fetching + decryption ─────────────────────────────────────────────

def fetch_and_decrypt(name: str, cfg: dict, vault: dict, password: str) -> tuple[list, dict]:
    recipient_alias = cfg.get("recipient_alias", "")
    secret          = cfg.get("secret", "")
    my_alias        = vault.get("my_alias", "ghost")
    recv_as         = my_alias

    if not secret:
        return [], vault

    fetch_time    = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    since         = cfg.get("last_fetched_at")
    sender_filter = recipient_alias if recipient_alias else None

    try:
        rows = sb_fetch(recv_as, since=since, sender_alias=sender_filter)
    except Exception as e:
        return [{"error": str(e)}], vault

    hist_data   = history_load(name, secret)
    known_blobs = hist_data.get("blobs", [])
    seen_set    = set(known_blobs)

    saved_salt_hex = cfg.get("salt_in")
    if saved_salt_hex:
        current_salt = bytes.fromhex(saved_salt_hex)
    else:
        current_salt = chain_next_salt(known_blobs[-1]) if known_blobs else chain_first_salt(secret)

    messages    = []
    vault_dirty = False

    for row in rows:
        blob   = row.get("blob", "") or ""
        row_id = row.get("id", "")
        ts_raw = row.get("created_at", "")
        sender = row.get("sender", name)

        if blob in seen_set:
            sb_delete(row_id)
            continue

        try:
            dt = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            ts = dt.strftime("%H:%M  %d %b %Y")
        except Exception:
            ts = ts_raw

        blob_index  = history_append_blob(name, blob, secret)
        known_blobs.append(blob)
        seen_set.add(blob)

        plaintext    = None
        chain_broken = False
        try:
            plaintext = msg_decrypt(blob, secret, current_salt)
        except Exception:
            recovered_salt = chain_reconstruct_salt(blob, secret, known_blobs)
            if recovered_salt is not None:
                try:
                    plaintext    = msg_decrypt(blob, secret, recovered_salt)
                    current_salt = recovered_salt
                except Exception:
                    chain_broken = True
            else:
                chain_broken = True

        messages.append({
            "name":         name,
            "row_id":       row_id,
            "issue_number": "",
            "ts":           ts,
            "ts_raw":       ts_raw,
            "blob":         blob,
            "blob_index":   blob_index,
            "plaintext":    plaintext,
            "chain_broken": chain_broken,
            "sender":       sender,
        })

        if plaintext is not None:
            history_append_message(name, ts_raw, plaintext, blob_index, secret, direction="in")
            current_salt = chain_next_salt(blob)
            vault["contacts"][name]["salt_in"] = current_salt.hex()
            vault_dirty = True
            sb_delete(row_id)

    vault["contacts"][name]["last_fetched_at"] = fetch_time
    vault_dirty = True

    if vault_dirty:
        vault_save(vault, password)

    return messages, vault


def do_send(name: str, cfg: dict, vault: dict, password: str, plaintext: str) -> tuple[Optional[str], dict, Optional[str]]:
    secret          = cfg.get("secret", "")
    alias           = vault.get("my_alias", "ghost")
    recipient_alias = cfg.get("recipient_alias", name)

    saved_salt_out = cfg.get("salt_out")
    if saved_salt_out:
        send_salt = bytes.fromhex(saved_salt_out)
    else:
        hist_data   = history_load(name, secret)
        known_blobs = hist_data.get("blobs", [])
        send_salt   = chain_next_salt(known_blobs[-1]) if known_blobs else chain_first_salt(secret)

    blob = msg_encrypt(plaintext, secret, send_salt)

    try:
        row_id = sb_send(alias, recipient_alias, blob)
    except Exception as e:
        return None, vault, str(e)

    blob_index = history_append_blob(name, blob, secret)
    ts_now     = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    history_append_message(name, ts_now, plaintext, blob_index, secret, direction="out")

    next_salt_out = chain_next_salt(blob)
    vault["contacts"][name]["salt_out"] = next_salt_out.hex()
    vault_save(vault, password)

    return row_id, vault, None


# ══════════════════════════════════════════════════════════════════════════════
#  POLLING SUBPROCESS  (unchanged from ghost-3-2.py)
# ══════════════════════════════════════════════════════════════════════════════

def _poll_worker_loop(
    result_queue: multiprocessing.Queue,
    input_queue: multiprocessing.Queue,
    vault_snapshot: dict,
    password: str,
    poll_interval: int,
    stop_event,
):
    import time
    while not stop_event.is_set():
        contacts = list(vault_snapshot.get("contacts", {}).items())
        for i, (name, cfg) in enumerate(contacts):
            if stop_event.is_set():
                break
            if i > 0:
                time.sleep(1)
            try:
                messages, updated_vault = fetch_and_decrypt(name, cfg, vault_snapshot, password)
                vault_snapshot = updated_vault
                result_queue.put({"type": "messages", "name": name, "messages": messages, "vault": updated_vault})
            except Exception as exc:
                result_queue.put({"type": "error", "name": name, "error": str(exc)})

        deadline = time.monotonic() + poll_interval
        while not stop_event.is_set() and time.monotonic() < deadline:
            while True:
                try:
                    msg = input_queue.get_nowait()
                    kind, payload = msg
                    if kind == "vault":
                        vault_snapshot = payload
                    elif kind == "interval":
                        poll_interval = payload
                        deadline = time.monotonic() + poll_interval
                except Exception:
                    break
            time.sleep(0.2)


class PollProcess:
    def __init__(self, vault: dict, password: str, interval: int = POLL_IDLE):
        self._password   = password
        self._interval   = interval
        self._result_q:  multiprocessing.Queue = multiprocessing.Queue()
        self._input_q:   multiprocessing.Queue = multiprocessing.Queue()
        self._stop       = multiprocessing.Event()
        self._vault_ref  = vault.copy()
        self._proc: Optional[multiprocessing.Process] = None

    def start(self):
        self._proc = multiprocessing.Process(
            target=_poll_worker_loop,
            args=(self._result_q, self._input_q, self._vault_ref,
                  self._password, self._interval, self._stop),
            daemon=True,
        )
        self._proc.start()

    def stop(self):
        self._stop.set()
        if self._proc and self._proc.is_alive():
            self._proc.join(timeout=3)
            if self._proc.is_alive():
                self._proc.kill()

    def set_interval(self, interval: int):
        if interval == self._interval:
            return
        self._interval = interval
        self._input_q.put(("interval", interval))

    def send_vault_update(self, vault: dict):
        self._vault_ref = vault.copy()
        self._input_q.put(("vault", self._vault_ref))

    def drain(self) -> list[dict]:
        results = []
        while True:
            try:
                results.append(self._result_q.get_nowait())
            except Exception:
                break
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREAD  (replaces Textual @work(thread=True))
# ══════════════════════════════════════════════════════════════════════════════

class WorkerThread(QThread):
    result = pyqtSignal(object)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn   = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            r = self._fn(*self._args, **self._kwargs)
            self.result.emit(r)
        except Exception as e:
            self.result.emit({"__error__": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
#  STYLES
# ══════════════════════════════════════════════════════════════════════════════

# Cyberpunk phosphor-green on black palette
STYLE = """
QMainWindow, QDialog, QWidget {
    background-color: #020402;
    color: #b8ffca;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 13px;
}

/* Sidebar */
#sidebar {
    background-color: #030603;
    border-right: 1px solid #003d10;
    min-width: 220px;
    max-width: 260px;
}
#sidebar-header {
    background-color: #000000;
    padding: 12px 10px 8px 10px;
    border-bottom: 1px solid #003d10;
}
#sidebar-title {
    color: #00ff41;
    font-size: 15px;
    font-weight: bold;
}
#sidebar-subtitle {
    color: #007a1f;
    font-size: 11px;
}
#sidebar-alias {
    color: #4d9960;
    font-size: 11px;
}

/* Contact list */
QListWidget {
    background-color: #030603;
    border: none;
    outline: none;
}
QListWidget::item {
    border-bottom: 1px solid #0d2615;
    padding: 8px 10px;
    color: #b8ffca;
}
QListWidget::item:hover {
    background-color: #0a1a0a;
}
QListWidget::item:selected {
    background-color: #0d240d;
    border-left: 3px solid #00ff41;
    color: #b8ffca;
}

/* Sidebar action buttons */
#btn-add-contact, #btn-settings {
    background-color: #000000;
    color: #4d9960;
    border: 1px solid #003d10;
    padding: 8px;
    text-align: left;
    font-family: "Consolas", "Courier New", monospace;
}
#btn-add-contact:hover {
    background-color: #071007;
    color: #00ff41;
    border-color: #00ff41;
}
#btn-settings:hover {
    background-color: #071007;
    color: #b8ffca;
}

/* Chat header */
#chat-header {
    background-color: #000000;
    border-bottom: 1px solid #003d10;
    padding: 6px 12px;
    min-height: 44px;
    max-height: 44px;
}
#chat-contact-name {
    color: #00ff41;
    font-weight: bold;
    font-size: 14px;
}
#chat-contact-alias {
    color: #1f4d2b;
    font-size: 11px;
}
#btn-check-now {
    background-color: #000000;
    color: #4d9960;
    border: 1px solid #003d10;
    padding: 4px 10px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
}
#btn-check-now:hover {
    background-color: #071007;
    color: #00ff41;
    border-color: #00ff41;
}

/* Message area */
#messages-area {
    background-color: #020402;
}
#welcome-widget {
    background-color: #020402;
}

/* Message bubbles */
.msg-sent {
    background-color: #071007;
    border-left: 3px solid #007a1f;
    border-radius: 0px;
    padding: 6px 10px;
    margin: 2px 6px;
    color: #b8ffca;
}
.msg-received {
    background-color: #020402;
    border-left: 3px solid #0d2615;
    padding: 6px 10px;
    margin: 2px 6px;
    color: #b8ffca;
}
.msg-broken {
    background-color: #020402;
    border-left: 3px solid #7a0f0f;
    padding: 6px 10px;
    margin: 2px 6px;
    color: #7a0f0f;
}

/* Compose area */
#compose-area {
    background-color: #000000;
    border-top: 1px solid #003d10;
    padding: 6px 8px;
}
#compose-input {
    background-color: #000000;
    color: #00ff41;
    border: 1px solid #003d10;
    padding: 6px 10px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 13px;
    selection-background-color: #0d240d;
}
#compose-input:focus {
    border-color: #00ff41;
    background-color: #071007;
}
#btn-send {
    background-color: #000000;
    color: #007a1f;
    border: 1px solid #003d10;
    padding: 6px 14px;
    font-family: "Consolas", "Courier New", monospace;
    font-weight: bold;
}
#btn-send:hover {
    background-color: #003d10;
    color: #39ff6e;
    border-color: #00ff41;
}
#btn-send:disabled {
    color: #0d2615;
    border-color: #0d2615;
}

/* Status bar */
#status-bar {
    background-color: #000000;
    border-top: 1px solid #003d10;
    padding: 2px 8px;
    min-height: 20px;
    max-height: 20px;
}
#status-left  { color: #1f4d2b; font-size: 11px; }
#status-right { color: #1f4d2b; font-size: 11px; }

/* Modals / Dialogs */
QDialog {
    background-color: #030603;
    border: 1px solid #007a1f;
}
QDialog QLabel {
    color: #4d9960;
    font-size: 12px;
}
QDialog QLineEdit {
    background-color: #000000;
    color: #00ff41;
    border: 1px solid #003d10;
    padding: 5px 8px;
    font-family: "Consolas", "Courier New", monospace;
}
QDialog QLineEdit:focus {
    border-color: #00ff41;
    background-color: #071007;
}
QDialog QPushButton {
    background-color: #071007;
    color: #00ff41;
    border: 1px solid #007a1f;
    padding: 6px 16px;
    font-family: "Consolas", "Courier New", monospace;
    font-weight: bold;
}
QDialog QPushButton:hover {
    background-color: #003d10;
    border-color: #00ff41;
}
QDialog QPushButton[flat="true"] {
    background-color: #000000;
    color: #4d9960;
    border-color: #0d2615;
}
#error-label { color: #ff2222; font-size: 12px; }
#success-label { color: #00ff41; font-size: 12px; }
"""


# ══════════════════════════════════════════════════════════════════════════════
#  UNLOCK DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class UnlockDialog(QDialog):
    """Password entry / vault creation at startup."""

    unlocked = pyqtSignal(dict, str)  # vault, password

    LOGO = (
        "  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗\n"
        " ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝\n"
        " ██║  ███╗███████║██║   ██║███████╗   ██║   \n"
        " ██║   ██║██╔══██║██║   ██║╚════██║   ██║   \n"
        " ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   \n"
        "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  "
    )

    def __init__(self):
        super().__init__()
        self._is_new        = not VAULT_PATH.exists()
        self._weak_pw_warned = False
        self.setWindowTitle("Ghost Messenger")
        self.setModal(True)
        self.setFixedWidth(480)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(24, 16, 24, 16)

        logo_lbl = QLabel(self.LOGO)
        logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_lbl.setStyleSheet("color: #00ff41; font-family: monospace; font-size: 12px;")
        layout.addWidget(logo_lbl)

        tagline = QLabel("── end-to-end encrypted  ·  supabase  ·  hash chain ──")
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline.setStyleSheet("color: #1f4d2b; font-size: 11px; padding: 4px 0;")
        layout.addWidget(tagline)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #003d10;")
        layout.addWidget(sep)

        if self._is_new:
            layout.addWidget(QLabel("// NEW VAULT — choose a strong master password"))
            self.pw1   = QLineEdit(); self.pw1.setPlaceholderText("Master password"); self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
            self.pw2   = QLineEdit(); self.pw2.setPlaceholderText("Confirm password"); self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
            self.alias = QLineEdit(); self.alias.setPlaceholderText("Your alias  (e.g. alice)")
            layout.addWidget(self.pw1)
            layout.addWidget(self.pw2)
            layout.addWidget(self.alias)
            btn_text = "[ INITIALIZE VAULT ]"
        else:
            layout.addWidget(QLabel("// VAULT FOUND — authenticate to continue"))
            self.pw1 = QLineEdit(); self.pw1.setPlaceholderText("Master password"); self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
            layout.addWidget(self.pw1)
            btn_text = "[ DECRYPT & ENTER ]"

        self.error_lbl = QLabel("")
        self.error_lbl.setObjectName("error-label")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.hide()
        layout.addWidget(self.error_lbl)

        btn = QPushButton(btn_text)
        btn.clicked.connect(self._do_unlock)
        layout.addWidget(btn)

        self.pw1.returnPressed.connect(btn.click)

    def _show_error(self, msg: str):
        self.error_lbl.setText(msg)
        self.error_lbl.show()

    def _do_unlock(self):
        pw1 = self.pw1.text()

        if self._is_new:
            pw2   = self.pw2.text()
            alias = self.alias.text().strip() or "ghost"

            if not pw1:
                self._show_error("Password cannot be empty.")
                return
            if pw1 != pw2:
                self._show_error("Passwords don't match.")
                return
            if len(pw1) < 12 and not self._weak_pw_warned:
                self._weak_pw_warned = True
                self._show_error(
                    "⚠  Password should be at least 12 characters. "
                    "Click again to proceed anyway."
                )
                return
            self._weak_pw_warned = False

            vault = vault_init(pw1)
            vault["my_alias"] = alias
            vault_save(vault, pw1)
            self.unlocked.emit(vault, pw1)
            self.accept()
        else:
            vault = vault_load(pw1)
            if vault is None:
                self._show_error("Wrong password. Try again.")
                self.pw1.clear()
                return
            self.unlocked.emit(vault, pw1)
            self.accept()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Return or event.key() == Qt.Key.Key_Enter:
            self._do_unlock()
        else:
            super().keyPressEvent(event)


# ══════════════════════════════════════════════════════════════════════════════
#  ADD CONTACT DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class AddContactDialog(QDialog):
    contact_added = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Contact")
        self.setFixedWidth(420)
        self._weak_warned = False
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(20, 16, 20, 16)

        layout.addWidget(QLabel("Add Contact"))

        info = QLabel(
            "Agree on aliases and a shared secret out-of-band.\n"
            "'Their alias' is what you address messages to them as.\n"
            "They must configure their alias to the same string."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #4d9960; font-size: 11px;")
        layout.addWidget(info)

        self.name   = QLineEdit(); self.name.setPlaceholderText("Contact name (e.g. Alice)")
        self.calias = QLineEdit(); self.calias.setPlaceholderText("Their alias in Supabase (e.g. alice)")
        self.secret = QLineEdit(); self.secret.setPlaceholderText("Shared secret / passphrase")
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.name)
        layout.addWidget(self.calias)
        layout.addWidget(self.secret)

        self.error_lbl = QLabel("")
        self.error_lbl.setObjectName("error-label")
        self.error_lbl.setWordWrap(True)
        self.error_lbl.hide()
        layout.addWidget(self.error_lbl)

        row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel"); cancel_btn.setProperty("flat", True)
        add_btn    = QPushButton("Add Contact")
        cancel_btn.clicked.connect(self.reject)
        add_btn.clicked.connect(self._add)
        row.addStretch()
        row.addWidget(cancel_btn)
        row.addWidget(add_btn)
        layout.addLayout(row)

    def _add(self):
        name   = self.name.text().strip()
        calias = self.calias.text().strip()
        secret = self.secret.text().strip()

        if not all([name, calias, secret]):
            self.error_lbl.setText("All fields are required.")
            self.error_lbl.show()
            return

        if len(secret) < 12 and not self._weak_warned:
            self._weak_warned = True
            self.error_lbl.setText(
                "⚠  Shared secret is short (< 12 chars). Click again to proceed anyway."
            )
            self.error_lbl.show()
            return
        self._weak_warned = False

        self.contact_added.emit({"name": name, "recipient_alias": calias, "secret": secret})
        self.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class SettingsDialog(QDialog):
    settings_saved = pyqtSignal(dict, str)  # vault, password

    def __init__(self, vault: dict, password: str, parent=None):
        super().__init__(parent)
        self._vault    = vault
        self._password = password
        self.setWindowTitle("Settings")
        self.setFixedWidth(440)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(20, 16, 20, 16)

        layout.addWidget(QLabel("Settings"))

        layout.addWidget(QLabel("Your alias"))
        self.alias_input = QLineEdit(self._vault.get("my_alias", "ghost"))
        layout.addWidget(self.alias_input)

        layout.addWidget(QLabel("Change master password"))
        self.pw_current = QLineEdit(); self.pw_current.setPlaceholderText("Current password"); self.pw_current.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_new     = QLineEdit(); self.pw_new.setPlaceholderText("New password");     self.pw_new.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_confirm = QLineEdit(); self.pw_confirm.setPlaceholderText("Confirm new password"); self.pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.pw_current)
        layout.addWidget(self.pw_new)
        layout.addWidget(self.pw_confirm)

        n_contacts = len(self._vault.get("contacts", {}))
        info_lbl = QLabel(
            f"Vault: {VAULT_PATH}\n"
            f"Contacts: {n_contacts}\n"
            f"History: {HISTORY_DIR}"
        )
        info_lbl.setStyleSheet("color: #1f4d2b; font-size: 11px;")
        layout.addWidget(info_lbl)

        self.error_lbl   = QLabel(""); self.error_lbl.setObjectName("error-label"); self.error_lbl.setWordWrap(True); self.error_lbl.hide()
        self.success_lbl = QLabel(""); self.success_lbl.setObjectName("success-label"); self.success_lbl.setWordWrap(True); self.success_lbl.hide()
        layout.addWidget(self.error_lbl)
        layout.addWidget(self.success_lbl)

        row = QHBoxLayout()
        close_btn = QPushButton("Close"); close_btn.setProperty("flat", True)
        save_btn  = QPushButton("Save")
        close_btn.clicked.connect(self.reject)
        save_btn.clicked.connect(self._save)
        row.addStretch()
        row.addWidget(close_btn)
        row.addWidget(save_btn)
        layout.addLayout(row)

    def _save(self):
        self.error_lbl.hide()
        self.success_lbl.hide()

        alias = self.alias_input.text().strip()
        if alias:
            self._vault["my_alias"] = alias
            vault_save(self._vault, self._password)

        pw_current = self.pw_current.text()
        pw_new     = self.pw_new.text()
        pw_confirm = self.pw_confirm.text()

        if pw_current or pw_new or pw_confirm:
            if vault_load(pw_current) is None:
                self.error_lbl.setText("✗  Current password is wrong.")
                self.error_lbl.show()
                return
            if pw_new != pw_confirm:
                self.error_lbl.setText("✗  New passwords don't match.")
                self.error_lbl.show()
                return
            if not pw_new:
                self.error_lbl.setText("✗  New password cannot be empty.")
                self.error_lbl.show()
                return
            vault_save(self._vault, pw_new)
            self._password = pw_new
            self.success_lbl.setText("✓  Password changed and vault re-encrypted.")
            self.success_lbl.show()
        else:
            self.success_lbl.setText("✓  Settings saved.")
            self.success_lbl.show()

        self.settings_saved.emit(self._vault, self._password)
        QTimer.singleShot(1000, self.accept)


# ══════════════════════════════════════════════════════════════════════════════
#  MESSAGE BUBBLE WIDGET
# ══════════════════════════════════════════════════════════════════════════════

class MessageBubble(QFrame):
    """Single message bubble — WhatsApp style, phosphor colour scheme."""

    def __init__(self, msg: dict, my_alias: str, contact_name: str, parent=None):
        super().__init__(parent)
        direction = msg.get("direction", "in")
        is_sent   = direction == "out"
        is_broken = not msg.get("plaintext") and not is_sent
        text      = msg.get("plaintext") or msg.get("text") or ""
        ts        = msg.get("ts", "")

        layout = QVBoxLayout(self)
        layout.setSpacing(2)
        layout.setContentsMargins(8, 4, 8, 4)

        if is_broken:
            self.setStyleSheet(
                "background-color:#020402; border-left:3px solid #7a0f0f;"
                "margin:2px 6px; padding:4px 8px;"
            )
            meta_lbl = QLabel(f"✖ CHAIN BROKEN  {ts}")
            meta_lbl.setStyleSheet("color:#7a0f0f; font-size:11px; font-weight:bold;")
            body_lbl = QLabel("// decryption failed — message unreadable")
            body_lbl.setStyleSheet("color:#7a0f0f; font-size:11px;")
            layout.addWidget(meta_lbl)
            layout.addWidget(body_lbl)
        elif is_sent:
            self.setStyleSheet(
                "background-color:#071007; border-left:3px solid #007a1f;"
                "margin:2px 6px; padding:4px 8px;"
            )
            meta_lbl = QLabel(f"▶ {my_alias}  {ts}")
            meta_lbl.setStyleSheet("color:#1f4d2b; font-size:11px;")
            body_lbl = QLabel(text)
            body_lbl.setWordWrap(True)
            body_lbl.setStyleSheet("color:#b8ffca;")
            body_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(meta_lbl)
            layout.addWidget(body_lbl)
        else:
            self.setStyleSheet(
                "background-color:#020402; border-left:3px solid #0d2615;"
                "margin:2px 6px; padding:4px 8px;"
            )
            meta_lbl = QLabel(f"◀ {contact_name}  {ts}")
            meta_lbl.setStyleSheet("color:#1f4d2b; font-size:11px;")
            body_lbl = QLabel(text)
            body_lbl.setWordWrap(True)
            body_lbl.setStyleSheet("color:#b8ffca;")
            body_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(meta_lbl)
            layout.addWidget(body_lbl)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)


# ══════════════════════════════════════════════════════════════════════════════
#  CONTACT LIST ITEM
# ══════════════════════════════════════════════════════════════════════════════

class ContactItemWidget(QWidget):
    def __init__(self, name: str, alias: str, unread: int = 0, n_msgs: int = 0, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 4)
        layout.setSpacing(1)

        unread_str = f"  ● {unread} new" if unread else ""
        name_lbl = QLabel(f"{name}{unread_str}")
        name_lbl.setStyleSheet("color:#b8ffca; font-weight:bold; font-size:13px;")
        alias_lbl = QLabel(f"→ {alias}")
        alias_lbl.setStyleSheet("color:#1f4d2b; font-size:11px;")

        layout.addWidget(name_lbl)
        layout.addWidget(alias_lbl)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class GhostMainWindow(QMainWindow):
    def __init__(self, vault: dict, password: str, offline: bool = False):
        super().__init__()
        self._vault          = vault
        self._password       = password
        self._offline        = offline
        self._active_contact: Optional[str] = None
        self._unread:         dict = {}
        self._msg_counts:     dict = {}
        self._poll_proc:      Optional[PollProcess] = None
        self._drain_timer:    Optional[QTimer] = None
        self._gear_timer:     Optional[QTimer] = None
        self._current_gear:   int = POLL_IDLE
        self._send_thread:    Optional[WorkerThread] = None
        self._fetch_thread:   Optional[WorkerThread] = None

        self.setWindowTitle("Ghost Messenger")
        self.resize(900, 640)
        self._build_ui()
        self._refresh_contact_list()
        self._setup_polling()
        self._setup_shortcuts()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        # Header
        header = QWidget()
        header.setObjectName("sidebar-header")
        hdr_layout = QVBoxLayout(header)
        hdr_layout.setContentsMargins(10, 10, 10, 8)
        hdr_layout.setSpacing(1)
        title_lbl = QLabel("// GHOST")
        title_lbl.setObjectName("sidebar-title")
        sub_lbl   = QLabel("secure messenger")
        sub_lbl.setObjectName("sidebar-subtitle")
        alias = self._vault.get("my_alias", "ghost")
        self.alias_lbl = QLabel(f"@{alias}")
        self.alias_lbl.setObjectName("sidebar-alias")
        hdr_layout.addWidget(title_lbl)
        hdr_layout.addWidget(sub_lbl)
        hdr_layout.addWidget(self.alias_lbl)
        sidebar_layout.addWidget(header)

        # Contact list
        self.contact_list = QListWidget()
        self.contact_list.itemClicked.connect(self._on_contact_selected)
        sidebar_layout.addWidget(self.contact_list, 1)

        # Action buttons
        btn_add = QPushButton("[ + ] new contact")
        btn_add.setObjectName("btn-add-contact")
        btn_add.clicked.connect(self._show_add_contact)
        btn_settings = QPushButton("[ ~ ] settings")
        btn_settings.setObjectName("btn-settings")
        btn_settings.clicked.connect(self._show_settings)
        sidebar_layout.addWidget(btn_add)
        sidebar_layout.addWidget(btn_settings)

        root.addWidget(sidebar)

        # ── Chat area ─────────────────────────────────────────────────────────
        chat_container = QWidget()
        chat_layout    = QVBoxLayout(chat_container)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)

        # Chat header
        chat_header = QWidget()
        chat_header.setObjectName("chat-header")
        ch_layout = QHBoxLayout(chat_header)
        ch_layout.setContentsMargins(12, 6, 8, 6)
        ch_layout.setSpacing(8)
        self.chat_contact_name  = QLabel("// no session")
        self.chat_contact_name.setObjectName("chat-contact-name")
        self.chat_contact_alias = QLabel("")
        self.chat_contact_alias.setObjectName("chat-contact-alias")
        self.btn_check_now = QPushButton("[ ↻ ] sync")
        self.btn_check_now.setObjectName("btn-check-now")
        self.btn_check_now.setFixedWidth(100)
        self.btn_check_now.clicked.connect(self._action_check_now)
        ch_layout.addWidget(self.chat_contact_name)
        ch_layout.addWidget(self.chat_contact_alias)
        ch_layout.addStretch()
        ch_layout.addWidget(self.btn_check_now)
        chat_layout.addWidget(chat_header)

        # Stack: welcome screen vs message scroll
        self.stack = QStackedWidget()
        self.stack.setObjectName("messages-area")

        # Welcome screen
        welcome = QWidget()
        welcome.setObjectName("welcome-widget")
        wl = QVBoxLayout(welcome)
        wl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_text = QLabel(
            "  ╔══════════════════════════════════════╗\n"
            "  ║         G H O S T  //  IDLE         ║\n"
            "  ╠══════════════════════════════════════╣\n"
            "  ║  select a contact  →  start session  ║\n"
            "  ║  Ctrl+N            →  new contact    ║\n"
            "  ║  Ctrl+R            →  check inbox    ║\n"
            f"  ╠══════════════════════════════════════╣\n"
            f"  ║  poll: {POLL_ACTIVE}s active · {POLL_IDLE}s idle"
            + ("  · OFFLINE" if self._offline else " " * 10)
            + "  ║\n"
            "  ╚══════════════════════════════════════╝"
        )
        welcome_text.setStyleSheet("color:#003d10; font-family:monospace;")
        welcome_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        wl.addWidget(welcome_text)
        self.stack.addWidget(welcome)  # index 0

        # Message scroll area
        self.scroll_area   = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border:none; background-color:#020402; }")
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.messages_container = QWidget()
        self.messages_container.setStyleSheet("background-color:#020402;")
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(0, 8, 0, 8)
        self.messages_layout.setSpacing(0)
        self.messages_layout.addStretch()

        self.scroll_area.setWidget(self.messages_container)
        self.stack.addWidget(self.scroll_area)  # index 1

        chat_layout.addWidget(self.stack, 1)

        # Compose area
        compose_widget = QWidget()
        compose_widget.setObjectName("compose-area")
        compose_layout = QHBoxLayout(compose_widget)
        compose_layout.setContentsMargins(8, 6, 8, 6)
        compose_layout.setSpacing(6)

        self.compose_input = QLineEdit()
        self.compose_input.setObjectName("compose-input")
        self.compose_input.setPlaceholderText("// type message — enter to transmit")
        self.compose_input.returnPressed.connect(self._do_send)

        self.btn_send = QPushButton("SEND ▶")
        self.btn_send.setObjectName("btn-send")
        self.btn_send.setFixedWidth(80)
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self._do_send)

        compose_layout.addWidget(self.compose_input)
        compose_layout.addWidget(self.btn_send)
        chat_layout.addWidget(compose_widget)

        # Status bar
        status_bar = QWidget()
        status_bar.setObjectName("status-bar")
        sb_layout = QHBoxLayout(status_bar)
        sb_layout.setContentsMargins(8, 0, 8, 0)
        self.status_left  = QLabel("// ready")
        self.status_left.setObjectName("status-left")
        self.status_right = QLabel("")
        self.status_right.setObjectName("status-right")
        sb_layout.addWidget(self.status_left)
        sb_layout.addStretch()
        sb_layout.addWidget(self.status_right)
        chat_layout.addWidget(status_bar)

        root.addWidget(chat_container, 1)

    # ── Shortcuts ─────────────────────────────────────────────────────────────

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self._show_add_contact)
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self._action_check_now)
        QShortcut(QKeySequence("Ctrl+,"), self).activated.connect(self._show_settings)

    # ── Polling setup ─────────────────────────────────────────────────────────

    def _setup_polling(self):
        if self._offline:
            self._set_status("Offline mode — local history only", "busy")
            return
        self._poll_proc = PollProcess(self._vault, self._password, interval=POLL_IDLE)
        self._poll_proc.start()

        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(300)
        self._drain_timer.timeout.connect(self._drain_poll_results)
        self._drain_timer.start()

    def _drain_poll_results(self):
        if not self._poll_proc:
            return
        for item in self._poll_proc.drain():
            if item.get("type") == "messages":
                self._on_bg_fetch_done(item["name"], item["messages"], item["vault"])
            elif item.get("type") == "error":
                self._set_status(f"Poll error ({item['name']}): {item['error']}", "error")

    def _shift_to_gear(self, interval: int, label: str):
        if self._current_gear == interval:
            return
        self._current_gear = interval
        if self._poll_proc:
            self._poll_proc.set_interval(interval)
        self._set_status(f"Poll → {interval}s ({label})", "ok")

    def _on_message_activity(self):
        self._shift_to_gear(POLL_ACTIVE, "active")
        if self._gear_timer:
            self._gear_timer.stop()
        self._gear_timer = QTimer(self)
        self._gear_timer.setSingleShot(True)
        self._gear_timer.setInterval(ACTIVE_TIMEOUT * 1000)
        self._gear_timer.timeout.connect(self._downshift_to_idle)
        self._gear_timer.start()

    def _downshift_to_idle(self):
        self._shift_to_gear(POLL_IDLE, "idle")

    # ── Contact list ──────────────────────────────────────────────────────────

    def _refresh_contact_list(self):
        contacts = self._vault.get("contacts", {}) if self._vault else {}
        self.contact_list.clear()

        for name, cfg in contacts.items():
            alias   = cfg.get("recipient_alias", "")
            unread  = self._unread.get(name, 0)
            n_msgs  = self._msg_counts.get(name, 0)

            item   = QListWidgetItem()
            widget = ContactItemWidget(name, alias, unread, n_msgs)
            item.setSizeHint(widget.sizeHint())
            item.setData(Qt.ItemDataRole.UserRole, name)
            self.contact_list.addItem(item)
            self.contact_list.setItemWidget(item, widget)

    def _on_contact_selected(self, item: QListWidgetItem):
        name = item.data(Qt.ItemDataRole.UserRole)
        if name:
            self._active_contact = name
            self.status_left.setText(f"// session: {name}")
            self._load_conversation(name)
            if not self._offline:
                self._on_message_activity()

    def _load_conversation(self, name: str):
        if not self._vault:
            return

        cfg   = self._vault.get("contacts", {}).get(name, {})
        alias = cfg.get("recipient_alias", "")

        self.chat_contact_name.setText(f"  {name}")
        self.chat_contact_alias.setText(f"→ {alias}")

        # Switch to message view
        self.stack.setCurrentIndex(1)

        # Clear existing messages
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        secret  = cfg.get("secret", "")
        hist    = history_load(name, secret)
        entries = hist.get("history", [])
        my_alias = self._vault.get("my_alias", "ghost")

        self._msg_counts[name] = len(entries)

        if not entries:
            placeholder = QLabel("\n  No messages yet. Send one or press Ctrl+R to check.")
            placeholder.setStyleSheet("color:#1f4d2b;")
            self.messages_layout.insertWidget(0, placeholder)
        else:
            for i, entry in enumerate(entries):
                bubble = MessageBubble(entry, my_alias, name)
                self.messages_layout.insertWidget(i, bubble)

        # Scroll to bottom
        QTimer.singleShot(50, self._scroll_to_bottom)

        # Enable compose
        self.btn_send.setEnabled(True)
        self.compose_input.setFocus()

        # Clear unread badge
        if name in self._unread:
            self._unread[name] = 0
            self._refresh_contact_list()

    def _scroll_to_bottom(self):
        sb = self.scroll_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _append_message_to_view(self, msg: dict):
        if self.stack.currentIndex() != 1:
            return
        my_alias = self._vault.get("my_alias", "ghost")
        name     = self._active_contact or ""
        bubble   = MessageBubble(msg, my_alias, name)
        # Insert before the trailing stretch
        pos = self.messages_layout.count() - 1
        self.messages_layout.insertWidget(pos, bubble)
        QTimer.singleShot(30, self._scroll_to_bottom)

    # ── Sending ───────────────────────────────────────────────────────────────

    def _do_send(self):
        if not self._active_contact or not self._vault:
            return
        text = self.compose_input.text().strip()
        if not text:
            return

        self.compose_input.clear()
        name = self._active_contact
        cfg  = self._vault.get("contacts", {}).get(name, {})

        self._set_status("Sending…", "busy")
        self.btn_send.setEnabled(False)

        self._send_thread = WorkerThread(do_send, name, cfg, self._vault, self._password, text)
        self._send_thread.result.connect(lambda r: self._on_send_done(name, text, r))
        self._send_thread.start()

    def _on_send_done(self, name: str, text: str, result):
        self.btn_send.setEnabled(True)
        if isinstance(result, dict) and "__error__" in result:
            self._set_status(f"Send failed: {result['__error__']}", "error")
            return

        row_id, vault, error = result
        self._vault = vault
        if self._poll_proc:
            self._poll_proc.send_vault_update(vault)

        if error:
            self._set_status(f"Send failed: {error}", "error")
            return

        self._set_status("Sent ✓", "ok")
        self._on_message_activity()

        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M  %d %b %Y")
        self._append_message_to_view({
            "direction":  "out",
            "text":       text,
            "plaintext":  text,
            "ts":         ts,
        })

    # ── Receiving (manual) ────────────────────────────────────────────────────

    def _action_check_now(self):
        if not self._active_contact or not self._vault:
            return
        if self._offline:
            self._set_status("Offline mode — network checks disabled", "busy")
            return
        name = self._active_contact
        cfg  = self._vault.get("contacts", {}).get(name, {})

        self.btn_check_now.setText("[ ↻ ] syncing…")
        self._set_status(f"Checking messages for {name}…", "busy")

        self._fetch_thread = WorkerThread(fetch_and_decrypt, name, cfg, self._vault, self._password)
        self._fetch_thread.result.connect(lambda r: self._on_fetch_done(name, r))
        self._fetch_thread.start()

    def _on_fetch_done(self, name: str, result):
        self.btn_check_now.setText("[ ↻ ] sync")
        if isinstance(result, dict) and "__error__" in result:
            self._set_status(f"Fetch failed: {result['__error__']}", "error")
            return

        messages, vault = result
        self._vault = vault
        if self._poll_proc:
            self._poll_proc.send_vault_update(vault)

        secret    = vault.get("contacts", {}).get(name, {}).get("secret", "")
        hist      = history_load(name, secret)
        known_idx = {e.get("blob_index") for e in hist.get("history", [])}
        new_msgs  = [m for m in messages if m.get("blob_index") not in known_idx and m.get("plaintext") is not None]

        if new_msgs:
            self._set_status(f"{len(new_msgs)} new message(s) from {name}", "ok")
            self._on_message_activity()
            if self._active_contact == name:
                self._load_conversation(name)
        else:
            errors = [m for m in messages if "error" in m]
            if errors:
                self._set_status(f"Error: {errors[0]['error']}", "error")
            else:
                self._set_status("No new messages.", "ok")

    def _on_bg_fetch_done(self, name: str, messages: list, vault: dict):
        self._vault = vault
        secret    = vault.get("contacts", {}).get(name, {}).get("secret", "")
        hist      = history_load(name, secret)
        known_idx = {e.get("blob_index") for e in hist.get("history", [])}
        new = [m for m in messages if m.get("plaintext") is not None and m.get("blob_index") not in known_idx]

        if new:
            if name != self._active_contact:
                self._unread[name] = self._unread.get(name, 0) + len(new)
                self._msg_counts[name] = self._msg_counts.get(name, 0) + len(new)
                self._refresh_contact_list()
            else:
                self._load_conversation(name)
            self._on_message_activity()
            count_str = "New messages" if len(new) > 1 else "New message"
            self._set_status(f"{count_str} from {name}", "ok")

    # ── UI helpers ────────────────────────────────────────────────────────────

    STATUS_COLORS = {
        "ok":    "#00ff41",
        "error": "#ff2222",
        "busy":  "#ffb300",
        "":      "#1f4d2b",
    }

    def _set_status(self, msg: str, level: str = ""):
        color = self.STATUS_COLORS.get(level, "#1f4d2b")
        self.status_right.setText(msg)
        self.status_right.setStyleSheet(f"color:{color}; font-size:11px;")

    # ── Dialogs ───────────────────────────────────────────────────────────────

    def _show_add_contact(self):
        dlg = AddContactDialog(self)
        dlg.contact_added.connect(self._on_add_contact_done)
        dlg.exec()

    def _on_add_contact_done(self, result: dict):
        if not result or not self._vault:
            return
        self._vault.setdefault("contacts", {})[result["name"]] = {
            "recipient_alias": result["recipient_alias"],
            "secret":          result["secret"],
        }
        vault_save(self._vault, self._password)
        self._refresh_contact_list()
        self._set_status(f"Contact '{result['name']}' added.", "ok")

    def _show_settings(self):
        dlg = SettingsDialog(self._vault, self._password, self)
        dlg.settings_saved.connect(self._on_settings_saved)
        dlg.exec()

    def _on_settings_saved(self, vault: dict, password: str):
        self._vault    = vault
        self._password = password
        self.alias_lbl.setText(f"@{vault.get('my_alias', 'ghost')}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def closeEvent(self, event):
        if self._drain_timer:
            self._drain_timer.stop()
        if self._gear_timer:
            self._gear_timer.stop()
        if self._poll_proc:
            self._poll_proc.stop()
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    multiprocessing.set_start_method("spawn", force=True)

    parser = argparse.ArgumentParser(description="ghost — encrypted messaging over Supabase")
    parser.add_argument("--offline", action="store_true", default=False,
                        help="Offline mode: browse local history only, no network calls")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)

    # Dark palette base so OS widgets inherit dark colours
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor("#020402"))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#b8ffca"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#000000"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#030603"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#b8ffca"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#b8ffca"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#071007"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#0d240d"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#00ff41"))
    app.setPalette(palette)

    # Show unlock dialog first
    unlock_dlg = UnlockDialog()

    main_win: Optional[GhostMainWindow] = None

    def on_unlocked(vault: dict, password: str):
        nonlocal main_win
        main_win = GhostMainWindow(vault, password, offline=args.offline)
        main_win.show()

    unlock_dlg.unlocked.connect(on_unlocked)
    result = unlock_dlg.exec()

    if main_win is None:
        sys.exit(0)

    sys.exit(app.exec())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
