import re
import sqlite3
import time
from urllib.parse import urlparse, parse_qs, unquote
import base64
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = "link_cache.db"
CACHE_TTL_SECONDS = 86400  # 24 hours server cache

PARAM_KEYS = [
    "url", "target", "dest", "destination", "redirect",
    "redirect_url", "return_url", "next", "u", "to",
    "link", "r", "q", "data", "href"
]


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resolved_links (
                source_url TEXT PRIMARY KEY,
                resolved_url TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        conn.commit()


def get_cached_link(source_url: str):
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT resolved_url, created_at FROM resolved_links WHERE source_url = ?",
            (source_url,)
        ).fetchone()
        if row and (now - row[1]) < CACHE_TTL_SECONDS:
            return row[0]
    return None


def save_cached_link(source_url: str, resolved_url: str):
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO resolved_links (source_url, resolved_url, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(source_url) DO UPDATE SET
                resolved_url = excluded.resolved_url,
                created_at = excluded.created_at
            """,
            (source_url, resolved_url, now)
        )
        conn.commit()


def is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def try_decode_base64(token: str):
    if not token or not re.fullmatch(r"[A-Za-z0-9+/_-]+=*", token.strip()):
        return None
    try:
        padded = token.strip().replace("-", "+").replace("_", "/")
        padded += "=" * ((4 - len(padded) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore").strip()
        if is_valid_http_url(decoded):
            return decoded
    except Exception:
        return None
    return None


def extract_embedded_target(url: str) -> str:
    current = url
    for _ in range(4):
        parsed = urlparse(current)
        qs = parse_qs(parsed.query)
        found = None

        for key in PARAM_KEYS:
            if key in qs and qs[key]:
                val = unquote(qs[key][0]).strip()
                if is_valid_http_url(val):
                    found = val
                    break
                b64 = try_decode_base64(val)
                if b64:
                    found = b64
                    break

        if not found:
            for seg in parsed.path.split("/"):
                seg_dec = unquote(seg).strip()
                if is_valid_http_url(seg_dec):
                    found = seg_dec
                    break
                if len(seg_dec) >= 10:
                    b64 = try_decode_base64(seg_dec)
                    if b64:
                        found = b64
                        break

        if found and found != current:
            current = found
        else:
            break
    return current


def follow_server_redirects(url: str) -> str:
    current = extract_embedded_target(url)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        )
    }

    try:
        resp = requests.get(current, headers=headers, allow_redirects=True, timeout=12)
        final_url = resp.url if is_valid_http_url(resp.url) else current
        final_url = extract_embedded_target(final_url)

        # Check HTML meta-refresh redirect if present
        if "text/html" in resp.headers.get("Content-Type", ""):
            match = re.search(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+\s*;\s*url=([^"\'>\s]+)',
                resp.text,
                re.IGNORECASE
            )
            if match:
                meta_target = match.group(1).strip()
                if is_valid_http_url(meta_target):
                    final_url = extract_embedded_target(meta_target)

        return final_url
    except Exception:
        return current


@app.route("/resolve", methods=["POST"])
def resolve_links():
    data = request.get_json(silent=True) or {}
    links = data.get("links", [])
    if not isinstance(links, list) or not links:
        return jsonify({"error": "No links provided"}), 400

    results = []
    for raw in links:
        clean_url = str(raw).strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "https://" + clean_url

        if not is_valid_http_url(clean_url):
            results.append({"resolvedUrl": clean_url, "cached": False})
            continue

        cached = get_cached_link(clean_url)
        if cached:
            results.append({"resolvedUrl": cached, "cached": True})
            continue

        resolved = follow_server_redirects(clean_url)
        save_cached_link(clean_url, resolved)
        results.append({"resolvedUrl": resolved, "cached": False})

    return jsonify({"results": results})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
