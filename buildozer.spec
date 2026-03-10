[app]

title = Ghost Messenger
package.name = ghostmessenger
package.domain = org.ghost

source.dir = .
source.main = ghost_kivy.py
source.include_exts = py,png,jpg,kv,atlas,json

version = 1.0

requirements = python3==3.10.14,kivy==2.3.0,httpx==0.27.0,cryptography,qrcode,pillow,certifi,anyio,sniffio,h11,httpcore

# Permissions
android.permissions = INTERNET,CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

# Android config
android.minapi = 26
android.api = 33
android.ndk = 25b
android.sdk = 33
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = True

# Orientation
orientation = portrait
fullscreen = 0

# Icons (optional — replace with your own)
# icon.filename = %(source.dir)s/icon.png
# presplash.filename = %(source.dir)s/presplash.png

[buildozer]
log_level = 2
warn_on_root = 1
