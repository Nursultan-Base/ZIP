#!/usr/bin/env python3
"""
ЗИП есепке алу — жергілікті желі сервері.

Іске қосу:
    python3 server.py

Осы компьютерден:      http://localhost:8000
Желідегі басқа компьютерлерден: http://<осы компьютердің IP-і>:8000

Барлық деректер осы серверде (data/ қалтасында) сақталады, сондықтан
желідегі барлық қолданушылар БІРДЕЙ деректерді көреді.

Кіру үшін логин/пароль қажет (үнсіз келісім бойынша admin / admin123 —
бірінші кіргеннен кейін «Қолданушылар» тақтасынан ауыстырыңыз).
"""
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import socket
import sys
import threading
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR можно переопределить переменной окружения — например, указать
# путь примонтированного постоянного диска на Railway (Volume), чтобы
# данные не терялись при каждом передеплое.
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(BASE_DIR, "data")
ITEMS_FILE = os.path.join(DATA_DIR, "items.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
COMPANIES_FILE = os.path.join(DATA_DIR, "companies.json")
DEFAULT_COMPANIES = [
    "ТОО «Оптиктелеком СтройСервис»",
    "ТОО «Азия Монтаж Групп»",
    "ТОО «SVitel (СКУД ЭсВител)»",
    "ИП «Канаев»",
]
FILES_DIR = os.path.join(DATA_DIR, "files")
STATIC_FILE = os.path.join(BASE_DIR, "index.html")
BG_DIR = os.path.join(BASE_DIR, "bg")
PORT = int(os.environ.get("PORT", 8000))
REALM = "ZIP esepke alu"
DEFAULT_ADMIN_PASSWORD = "admin123"

os.makedirs(FILES_DIR, exist_ok=True)
if not os.path.exists(ITEMS_FILE):
    with open(ITEMS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

ITEMS_LOCK = threading.Lock()


def read_items():
    try:
        with open(ITEMS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def write_items(items):
    tmp_path = ITEMS_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, ITEMS_FILE)


def upsert_item(item):
    """Insert or replace a single item by id. Locked so two users saving
    at the same time cannot silently overwrite each other's changes."""
    with ITEMS_LOCK:
        items = read_items()
        idx = next((i for i, it in enumerate(items) if it.get("id") == item.get("id")), None)
        if idx is None:
            items.append(item)
        else:
            items[idx] = item
        write_items(items)
    return item


def delete_item(item_id):
    with ITEMS_LOCK:
        items = read_items()
        items = [it for it in items if it.get("id") != item_id]
        write_items(items)


COMPANIES_LOCK = threading.Lock()

if not os.path.exists(COMPANIES_FILE):
    with open(COMPANIES_FILE, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_COMPANIES, f, ensure_ascii=False, indent=2)


def read_companies():
    try:
        with open(COMPANIES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return list(DEFAULT_COMPANIES)


def write_companies(companies):
    tmp_path = COMPANIES_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(companies, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, COMPANIES_FILE)


def safe_id(item_id):
    return "".join(c for c in item_id if c.isalnum() or c in "-_")


def file_path(item_id):
    return os.path.join(FILES_DIR, safe_id(item_id) + ".json")


# ---- пайдаланушылар / auth ----

def hash_password(password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000).hex()


def make_user(username, name, password, role):
    salt = secrets.token_hex(16)
    return {
        "username": username,
        "name": name,
        "role": role,
        "salt": salt,
        "hash": hash_password(password, salt),
    }


USERS_LOCK = threading.Lock()


def read_users():
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def write_users(users):
    tmp_path = USERS_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, USERS_FILE)


def make_backup_zip():
    buf = io.BytesIO()
    with ITEMS_LOCK, USERS_LOCK, COMPANIES_LOCK:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(DATA_DIR):
                for name in files:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, DATA_DIR)
                    zf.write(full, rel)
    buf.seek(0)
    return buf.read()


def restore_backup_zip(raw_bytes):
    with ITEMS_LOCK, USERS_LOCK, COMPANIES_LOCK:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for name in zf.namelist():
                # guard against zip-slip: only allow paths that stay inside DATA_DIR
                dest = os.path.normpath(os.path.join(DATA_DIR, name))
                if not dest.startswith(os.path.normpath(DATA_DIR) + os.sep):
                    continue
                if name.endswith("/"):
                    os.makedirs(dest, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(name) as src, open(dest, "wb") as out:
                    out.write(src.read())


if not os.path.exists(USERS_FILE):
    write_users([make_user("admin", "Администратор", DEFAULT_ADMIN_PASSWORD, "admin")])


def find_user(username):
    for u in read_users():
        if u["username"] == username:
            return u
    return None


def verify_user(username, password):
    u = find_user(username)
    if not u:
        return None
    if hmac.compare_digest(hash_password(password, u["salt"]), u["hash"]):
        return u
    return None


def public_user(u):
    return {"username": u["username"], "name": u["name"], "role": u["role"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "ZIPServer/1.0"

    def log_message(self, format, *args):
        pass  # консольді бос сөзден тазарту үшін

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        if not os.path.exists(path):
            self.send_response(404)
            self.end_headers()
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_auth(self):
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
                username, _, password = decoded.partition(":")
                user = verify_user(username, password)
                if user:
                    return user
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("Авторизация қажет / Требуется авторизация".encode("utf-8"))
        return None

    def _require_admin(self, user):
        if user["role"] != "admin":
            self._send_json({"error": "forbidden"}, 403)
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        user = self._require_auth()
        if not user:
            return

        if path in ("/", "/index.html"):
            return self._send_file(STATIC_FILE, "text/html; charset=utf-8")

        if path.startswith("/bg/"):
            name = os.path.basename(path)
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            return self._send_file(os.path.join(BG_DIR, name), ctype)

        if path == "/api/whoami":
            return self._send_json(public_user(user))

        if path == "/api/items":
            return self._send_json(read_items())

        if path == "/api/companies":
            return self._send_json(read_companies())

        if path == "/api/users":
            if not self._require_admin(user):
                return
            return self._send_json([public_user(u) for u in read_users()])

        if path.startswith("/api/files/"):
            item_id = path.split("/api/files/", 1)[1]
            fp = file_path(item_id)
            if os.path.exists(fp):
                with open(fp, "r", encoding="utf-8") as f:
                    return self._send_json(json.load(f))
            return self._send_json({"error": "not found"}, 404)

        if path == "/api/backup":
            if not self._require_admin(user):
                return
            body = make_backup_zip()
            stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="zip-backup-{stamp}.zip"')
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        user = self._require_auth()
        if not user:
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""

        if path == "/api/items":
            # Full-list replace, kept only for bulk imports (e.g. restoring a backup).
            try:
                items = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            with ITEMS_LOCK:
                write_items(items)
            return self._send_json({"ok": True})

        if path == "/api/restore":
            if not self._require_admin(user):
                return
            try:
                restore_backup_zip(raw)
            except Exception:
                return self._send_json({"error": "bad zip"}, 400)
            return self._send_json({"ok": True})

        if path.startswith("/api/items/"):
            item_id = path.split("/api/items/", 1)[1]
            try:
                item = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            if item.get("id") != item_id:
                return self._send_json({"error": "id mismatch"}, 400)
            upsert_item(item)
            return self._send_json({"ok": True})

        if path == "/api/users":
            if not self._require_admin(user):
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            username = (payload.get("username") or "").strip()
            name = (payload.get("name") or "").strip()
            role = payload.get("role") if payload.get("role") in ("admin", "user") else "user"
            password = payload.get("password") or ""
            if not username or not name:
                return self._send_json({"error": "username and name required"}, 400)
            with USERS_LOCK:
                users = read_users()
                existing = next((u for u in users if u["username"] == username), None)
                if existing:
                    existing["name"] = name
                    existing["role"] = role
                    if password:
                        existing["salt"] = secrets.token_hex(16)
                        existing["hash"] = hash_password(password, existing["salt"])
                else:
                    if not password:
                        return self._send_json({"error": "password required for new user"}, 400)
                    users.append(make_user(username, name, password, role))
                write_users(users)
            return self._send_json({"ok": True})

        if path.startswith("/api/files/"):
            item_id = path.split("/api/files/", 1)[1]
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            with open(file_path(item_id), "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            return self._send_json({"ok": True})

        if path == "/api/companies":
            if not self._require_admin(user):
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            name = (payload.get("name") or "").strip()
            if not name:
                return self._send_json({"error": "name required"}, 400)
            with COMPANIES_LOCK:
                companies = read_companies()
                if name in companies:
                    return self._send_json({"error": "already exists"}, 400)
                companies.append(name)
                write_companies(companies)
            return self._send_json(companies)

        if path == "/api/companies/rename":
            if not self._require_admin(user):
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._send_json({"error": "bad json"}, 400)
            old_name = (payload.get("oldName") or "").strip()
            new_name = (payload.get("newName") or "").strip()
            if not old_name or not new_name:
                return self._send_json({"error": "oldName and newName required"}, 400)
            with COMPANIES_LOCK, ITEMS_LOCK:
                companies = read_companies()
                if old_name not in companies:
                    return self._send_json({"error": "not found"}, 404)
                if new_name != old_name and new_name in companies:
                    return self._send_json({"error": "already exists"}, 400)
                companies = [new_name if c == old_name else c for c in companies]
                write_companies(companies)
                items = read_items()
                for it in items:
                    if it.get("company") == old_name:
                        it["company"] = new_name
                write_items(items)
            return self._send_json(companies)

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        path = urlparse(self.path).path
        user = self._require_auth()
        if not user:
            return

        if path.startswith("/api/files/"):
            item_id = path.split("/api/files/", 1)[1]
            fp = file_path(item_id)
            if os.path.exists(fp):
                os.remove(fp)
            return self._send_json({"ok": True})

        if path.startswith("/api/items/"):
            item_id = path.split("/api/items/", 1)[1]
            delete_item(item_id)
            return self._send_json({"ok": True})

        if path.startswith("/api/companies/"):
            if not self._require_admin(user):
                return
            name = unquote(path.split("/api/companies/", 1)[1])
            with COMPANIES_LOCK, ITEMS_LOCK:
                if any(it.get("company") == name for it in read_items()):
                    return self._send_json({"error": "company has items"}, 400)
                companies = [c for c in read_companies() if c != name]
                write_companies(companies)
            return self._send_json(companies)

        if path.startswith("/api/users/"):
            if not self._require_admin(user):
                return
            username = path.split("/api/users/", 1)[1]
            with USERS_LOCK:
                users = read_users()
                admins_left = sum(1 for u in users if u["role"] == "admin")
                target = next((u for u in users if u["username"] == username), None)
                if target and target["role"] == "admin" and admins_left <= 1:
                    return self._send_json({"error": "cannot remove the last admin"}, 400)
                users = [u for u in users if u["username"] != username]
                write_users(users)
            return self._send_json({"ok": True})

        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    ip = get_local_ip()
    print("=" * 56)
    print(" ЗИП есепке алу сервері іске қосылды")
    print(f"   Осы компьютерден:              http://localhost:{PORT}")
    print(f"   Желідегі басқа компьютерлерден: http://{ip}:{PORT}")
    print(" Кіру: admin / admin123 (бірінші кіргеннен кейін ауыстырыңыз)")
    print("=" * 56)
    print(" Тоқтату үшін: Ctrl+C")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
