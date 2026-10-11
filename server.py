"""
CloudBrowse — Python backend
Requires: Python 3.9+, playwright, and the Chromium browser it installs.

Quick start:
  pip install -r requirements.txt
  playwright install chromium
  python server.py

Environment variables (see .env.example):
  PORT            - port to listen on  (default 8000)
  ALLOWED_ORIGIN  - your frontend domain for CORS  (default * for dev)
  API_KEY         - optional secret; if set, clients must send X-API-Key header
  SESSION_TIMEOUT - seconds before idle session closes  (default 600)
  MAX_SESSIONS    - max concurrent sessions  (default 10)
"""

import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import secrets
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs
import threading

# ── Config from environment ───────────────────────────────────────────────────
PORT            = int(os.environ.get("PORT", 8000))
ALLOWED_ORIGIN  = os.environ.get("ALLOWED_ORIGIN", "*")
API_KEY         = os.environ.get("API_KEY", "")          # empty = no auth required
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", 600))
MAX_SESSIONS    = int(os.environ.get("MAX_SESSIONS", 10))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cloudbrowse")

# ── Playwright setup (async, in a dedicated event loop) ───────────────────────
_loop     = None   # the asyncio event loop that owns playwright
_playwright_obj = None
_browser  = None

def get_loop():
    return _loop

def run_async(coro):
    """Run an async coroutine from a sync context (the HTTP handler thread)."""
    fut = asyncio.run_coroutine_threadsafe(coro, _loop)
    return fut.result(timeout=60)

# ── Session storage ───────────────────────────────────────────────────────────
_sessions = {}        # session_id -> dict
_sessions_lock = threading.Lock()

def _new_session_dict(page, context):
    return {
        "page":       page,
        "context":    context,
        "created_at": time.time(),
        "last_used":  time.time(),
        "id":         None,          # filled after creation
    }

# ── URL safety ────────────────────────────────────────────────────────────────
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "169.254.169.254",   # AWS metadata
    "metadata.google.internal",
}
BLOCKED_SCHEMES = {"file", "ftp", "javascript", "data", "vbscript", "about"}

def is_safe_url(raw: str) -> tuple[bool, str]:
    """Return (ok, reason). Blocks private IPs and dangerous schemes."""
    try:
        parsed = urlparse(raw)
    except Exception:
        return False, "Could not parse URL"

    if parsed.scheme.lower() in BLOCKED_SCHEMES:
        return False, f"Scheme '{parsed.scheme}' is not allowed"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Only http and https URLs are supported"

    host = parsed.hostname or ""
    if not host:
        return False, "URL has no host"

    if host.lower() in BLOCKED_HOSTS:
        return False, f"Access to '{host}' is blocked"

    # Block private/loopback/link-local IP ranges
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False, f"Access to private IP {host} is blocked"
    except ValueError:
        pass  # it's a hostname, not an IP — that's fine

    return True, ""

# ── Playwright async helpers ──────────────────────────────────────────────────
async def _playwright_start():
    global _playwright_obj, _browser
    from playwright.async_api import async_playwright
    _playwright_obj = await async_playwright().start()
    _browser = await _playwright_obj.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]
    )
    log.info("Playwright Chromium started")

async def _create_session_async():
    context = await _browser.new_context(
        viewport={"width": 1280, "height": 800},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    )
    page = await context.new_page()
    return page, context

async def _navigate_async(page, url: str):
    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    await page.wait_for_timeout(500)

async def _screenshot_async(page) -> bytes:
    return await page.screenshot(type="png", full_page=False)

async def _click_async(page, x: int, y: int):
    await page.mouse.click(x, y)
    await page.wait_for_timeout(400)

async def _key_async(page, key: str):
    await page.keyboard.press(key)
    await page.wait_for_timeout(150)

async def _type_async(page, text: str):
    await page.keyboard.type(text)
    await page.wait_for_timeout(150)

async def _scroll_async(page, delta_y: int):
    await page.mouse.wheel(0, delta_y)
    await page.wait_for_timeout(150)

async def _reload_async(page):
    await page.reload(wait_until="domcontentloaded", timeout=30000)
    await page.wait_for_timeout(500)

async def _close_session_async(session):
    try:
        await session["page"].close()
        await session["context"].close()
    except Exception:
        pass

async def _get_page_info_async(page):
    url   = page.url
    title = await page.title()
    return {"current_url": url, "title": title}

# ── Session manager ───────────────────────────────────────────────────────────
def create_session():
    with _sessions_lock:
        if len(_sessions) >= MAX_SESSIONS:
            raise RuntimeError(f"Server is at capacity ({MAX_SESSIONS} sessions). Try again later.")
    page, context = run_async(_create_session_async())
    sid = str(uuid.uuid4())
    s   = _new_session_dict(page, context)
    s["id"] = sid
    with _sessions_lock:
        _sessions[sid] = s
    log.info(f"Session created: {sid}")
    return sid

def get_session(sid: str):
    with _sessions_lock:
        s = _sessions.get(sid)
    if not s:
        raise KeyError("Session not found. It may have expired — please reload.")
    s["last_used"] = time.time()
    return s

def delete_session(sid: str):
    with _sessions_lock:
        s = _sessions.pop(sid, None)
    if s:
        run_async(_close_session_async(s))
        log.info(f"Session closed: {sid}")

# ── Background task: expire idle sessions ─────────────────────────────────────
def _reaper():
    while True:
        time.sleep(60)
        now = time.time()
        to_kill = []
        with _sessions_lock:
            for sid, s in list(_sessions.items()):
                if now - s["last_used"] > SESSION_TIMEOUT:
                    to_kill.append(sid)
        for sid in to_kill:
            log.info(f"Expiring idle session {sid}")
            delete_session(sid)

# ── HTTP handler ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        log.info("%s - %s" % (self.client_address[0], fmt % args))

    # ── CORS pre-flight ──
    def do_OPTIONS(self):
        self._send_cors(200)
        self.end_headers()

    # ── GET ──
    def do_GET(self):
        path, qs = self._parse_path()

        # health check
        if path == "/health":
            return self._json({"status": "ok", "sessions": len(_sessions)})

        if path == "/session/screenshot":
            if not self._auth(): return
            sid = qs.get("session_id", [""])[0]
            try:
                s      = get_session(sid)
                png    = run_async(_screenshot_async(s["page"]))
                b64    = base64.b64encode(png).decode()
                return self._json({"image_b64": b64})
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/info":
            if not self._auth(): return
            sid = qs.get("session_id", [""])[0]
            try:
                s    = get_session(sid)
                info = run_async(_get_page_info_async(s["page"]))
                return self._json(info)
            except Exception as e:
                return self._error(str(e), 400)

        return self._error("Not found", 404)

    # ── POST ──
    def do_POST(self):
        path, _ = self._parse_path()
        try:
            body = self._read_body()
        except Exception as e:
            return self._error("Bad request body: " + str(e), 400)

        if path == "/session/create":
            if not self._auth(): return
            try:
                sid = create_session()
                return self._json({"session_id": sid})
            except Exception as e:
                return self._error(str(e), 503)

        if path == "/session/navigate":
            if not self._auth(): return
            sid = body.get("session_id", "")
            url = body.get("url", "")
            ok, reason = is_safe_url(url)
            if not ok:
                return self._error(f"URL blocked: {reason}", 400)
            try:
                s = get_session(sid)
                run_async(_navigate_async(s["page"], url))
                info = run_async(_get_page_info_async(s["page"]))
                return self._json(info)
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/click":
            if not self._auth(): return
            sid = body.get("session_id", "")
            x   = int(body.get("x", 0))
            y   = int(body.get("y", 0))
            try:
                s = get_session(sid)
                run_async(_click_async(s["page"], x, y))
                info = run_async(_get_page_info_async(s["page"]))
                return self._json(info)
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/key":
            if not self._auth(): return
            sid = body.get("session_id", "")
            key = body.get("key", "")
            try:
                s = get_session(sid)
                run_async(_key_async(s["page"], key))
                return self._json({"ok": True})
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/scroll":
            if not self._auth(): return
            sid     = body.get("session_id", "")
            delta_y = int(body.get("delta_y", 0))
            try:
                s = get_session(sid)
                run_async(_scroll_async(s["page"], delta_y))
                return self._json({"ok": True})
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/reload":
            if not self._auth(): return
            sid = body.get("session_id", "")
            try:
                s = get_session(sid)
                run_async(_reload_async(s["page"]))
                info = run_async(_get_page_info_async(s["page"]))
                return self._json(info)
            except Exception as e:
                return self._error(str(e), 400)

        if path == "/session/close":
            if not self._auth(): return
            sid = body.get("session_id", "")
            delete_session(sid)
            return self._json({"ok": True})

        return self._error("Not found", 404)

    # ── Helpers ──
    def _parse_path(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length) if length else b"{}"
        return json.loads(raw)

    def _auth(self) -> bool:
        if not API_KEY:
            return True  # no key configured → open
        provided = self.headers.get("X-API-Key", "")
        if not secrets.compare_digest(provided, API_KEY):
            self._error("Unauthorized", 401)
            return False
        return True

    def _send_cors(self, code):
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin",  ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Api-Key")
        self.send_header("Cache-Control", "no-store")

    def _json(self, data: dict, code: int = 200):
        payload = json.dumps(data).encode()
        self._send_cors(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, msg: str, code: int = 500):
        self._json({"error": msg}, code)

# ── Entry point ───────────────────────────────────────────────────────────────
def _run_event_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

def main():
    global _loop

    # 1. Start the asyncio event loop in a background thread
    _loop = asyncio.new_event_loop()
    t = Thread(target=_run_event_loop, args=(_loop,), daemon=True)
    t.start()

    # 2. Start Playwright in that loop
    run_async(_playwright_start())

    # 3. Start session reaper
    Thread(target=_reaper, daemon=True).start()

    # 4. Start HTTP server
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    log.info(f"CloudBrowse backend running on http://0.0.0.0:{PORT}")
    if API_KEY:
        log.info("API key authentication is ENABLED")
    else:
        log.warning("API key authentication is DISABLED — set API_KEY env var in production")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()

if __name__ == "__main__":
    main()
