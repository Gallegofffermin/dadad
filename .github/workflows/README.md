# Ghost Messenger

End-to-end encrypted messaging over Supabase. AES-GCM + hash chain forward secrecy.

## Apps

| File | Platform | Description |
|------|----------|-------------|
| `ghost_qt.py` | Desktop (Windows/Mac/Linux) | PyQt6 GUI |
| `ghost_kivy.py` | Mobile (Android/iOS) | Kivy touch UI |

Both apps share the same vault and history files (`~/.ghost_vault.enc`, `~/.ghost_history/`).

---

## Android APK — GitHub Actions build

Every push to `main` automatically builds an APK.

**To download your APK:**
1. Go to the **Actions** tab in this repo
2. Click the latest **Build Ghost Messenger APK** run
3. Scroll to **Artifacts** at the bottom
4. Download **ghost-messenger-apk**
5. Unzip it and copy the `.apk` to your phone
6. On your phone: Settings → Security → allow **Install unknown apps**
7. Tap the APK to install

---

## Desktop install

```bash
pip install PyQt6 httpx cryptography qrcode[pil] opencv-python pillow
python ghost_qt.py
```

## Mobile (run without building)

```bash
pip install kivy httpx cryptography qrcode[pil] pillow
python ghost_kivy.py
```

---

## Supabase setup

Create a table called `ghost_messages` with these columns:

```sql
create table ghost_messages (
  id uuid default gen_random_uuid() primary key,
  sender text not null,
  recipient text not null,
  blob text not null,
  created_at timestamptz default now()
);
```

Then set credentials via environment variables or `~/.ghost_config`:

```ini
[supabase]
url = https://YOUR_PROJECT.supabase.co
key = YOUR_ANON_KEY
```

---

## QR Contact Sharing

1. Both parties agree on a **shared secret** out-of-band
2. One person: select the contact → **[QR] Share** → show QR
3. Other person: **[⬛] Scan QR** → point camera at the code
4. Contact is added automatically with alias + secret pre-filled
