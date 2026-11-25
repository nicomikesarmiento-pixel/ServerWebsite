import base64
import json
import re
import sqlite3
import time
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = "link_cache.db"
CACHE_TTL_SECONDS = 86400
MAX_LINKS_PER_REQUEST = 15
MAX_REDIRECT_HOPS = 6
REQUEST_TIMEOUT_SECONDS = 8

PARAM_KEYS = [
    "url", "target", "dest", "destination", "redirect",
    "redirect_url", "return_url", "next", "u", "to",
    "link", "r", "q", "data", "href", "go", "out", "uri"
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resolved_links (
                    source_url TEXT PRIMARY KEY,
                    resolved_url TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.commit()
    except Exception:
        pass


init_db()


def get_cached_link(source_url: str):
    try:
        now = int(time.time())
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            row = conn.execute(
                "SELECT resolved_url, created_at FROM resolved_links WHERE source_url = ?",
                (source_url,),
            ).fetchone()
            if row and (now - int(row[1])) < CACHE_TTL_SECONDS:
                return row[0]
    except Exception:
        return None
    return None


def save_cached_link(source_url: str, resolved_url: str) -> None:
    try:
        now = int(time.time())
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                """
                INSERT INTO resolved_links (source_url, resolved_url, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(source_url) DO UPDATE SET
                    resolved_url = excluded.resolved_url,
                    created_at = excluded.created_at
                """,
                (source_url, resolved_url, now),
            )
            conn.commit()
    except Exception:
        pass


def normalize_input_url(raw_value: str):
    candidate = str(raw_value or "").strip()
    if not candidate or len(candidate) > 4096:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate
    return candidate if is_valid_http_url(candidate) else None


def is_valid_http_url(url: str) -> bool:
    try:
        if not url or len(url) > 4096:
            return False
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        if parsed.scheme not in ("http", "https") or not host:
            return False
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False
        return "." in host
    except Exception:
        return False


def try_decode_base64(token: str):
    cleaned = str(token or "").strip()
    if not cleaned or len(cleaned) > 2048:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", cleaned):
        return None
    try:
        padded = cleaned.replace("-", "+").replace("_", "/")
        padded += "=" * ((4 - len(padded) % 4) % 4)
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore").strip()
        if not decoded:
            return None
        if is_valid_http_url(decoded):
            return decoded
        if decoded.startswith("{") or decoded.startswith("["):
            obj = json.loads(decoded)
            found_from_json = find_url_in_object(obj)
            if found_from_json:
                return found_from_json
    except Exception:
        return None
    return None


def find_url_in_object(obj):
    if isinstance(obj, str):
        val = obj.strip()
        if is_valid_http_url(val):
            return val
        return try_decode_base64(val)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in PARAM_KEYS:
                res = find_url_in_object(v)
                if res:
                    return res
        for v in obj.values():
            res = find_url_in_object(v)
            if res:
                return res
    if isinstance(obj, list):
        for item in obj:
            res = find_url_in_object(item)
            if res:
                return res
    return None


def extract_embedded_target(url: str) -> str:
    current = url
    try:
        for _ in range(4):
            parsed = urlparse(current)
            qs = parse_qs(parsed.query, keep_blank_values=False)
            found = None

            for key in PARAM_KEYS:
                if key in qs and qs[key]:
                    val = unquote(qs[key][0]).strip()
                    if is_valid_http_url(val):
                        found = val
                        break
                    decoded_val = try_decode_base64(val)
                    if decoded_val:
                        found = decoded_val
                        break

            if not found:
                for seg in parsed.path.split("/"):
                    seg_dec = unquote(seg).strip()
                    if not seg_dec:
                        continue
                    if is_valid_http_url(seg_dec):
                        found = seg_dec
                        break
                    if 8 <= len(seg_dec) <= 1024:
                        decoded_seg = try_decode_base64(seg_dec)
                        if decoded_seg:
                            found = decoded_seg
                            break

            if found and found != current and is_valid_http_url(found):
                current = found
            else:
                break
    except Exception:
        return current
    return current


def extract_html_redirect(base_url: str, html_text: str):
    if not html_text:
        return None
    snippet = html_text[:65536]

    meta_match = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?[^"\']*url\s*=\s*([^"\'>\s;]+)',
        snippet,
        re.IGNORECASE,
    )
    if meta_match:
        candidate = urljoin(base_url, unquote(meta_match.group(1).strip()))
        if is_valid_http_url(candidate):
            return candidate

    js_match = re.search(
        r'(?:window\.location(?:\.href)?|location\.href|location\.replace)\s*=\s*["\']([^"\']+)["\']',
        snippet,
        re.IGNORECASE,
    )
    if js_match:
        candidate = urljoin(base_url, unquote(js_match.group(1).strip()))
        if is_valid_http_url(candidate):
            return candidate

    return None


def follow_server_redirects(url: str) -> str:
    current = extract_embedded_target(url)
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    try:
        for _ in range(MAX_REDIRECT_HOPS):
            current = extract_embedded_target(current)
            resp = session.get(
                current,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT_SECONDS,
                stream=True,
            )
            final_url = resp.url if is_valid_http_url(resp.url) else current
            final_url = extract_embedded_target(final_url)

            content_type = resp.headers.get("Content-Type", "").lower()
            next_url = None
            if "text/html" in content_type or "application/xhtml" in content_type:
                raw_html = resp.content[:65536].decode(resp.encoding or "utf-8", errors="ignore")
                next_url = extract_html_redirect(final_url, raw_html)

            resp.close()

            if next_url and is_valid_http_url(next_url) and next_url != final_url:
                current = next_url
            else:
                current = final_url
                break
    except Exception:
        return extract_embedded_target(current)
    finally:
        try:
            session.close()
        except Exception:
            pass

    return current


def process_single_link(raw_link: str) -> dict:
    clean_url = normalize_input_url(raw_link)
    if not clean_url:
        fallback = str(raw_link or "").strip()
        return {"resolvedUrl": fallback, "cached": False}

    cached = get_cached_link(clean_url)
    if cached:
        return {"resolvedUrl": cached, "cached": True}

    resolved = follow_server_redirects(clean_url)
    if not is_valid_http_url(resolved):
        resolved = clean_url

    save_cached_link(clean_url, resolved)
    return {"resolvedUrl": resolved, "cached": False}


@app.route("/", methods=["GET"])
def index_route():
    return jsonify({
        "service": "Delta Link Resolver API",
        "status": "online",
        "endpoints": ["/health", "/resolve"]
    })


@app.route("/health", methods=["GET"])
def health_route():
    return jsonify({"status": "ok"})


@app.route("/resolve", methods=["POST"])
def resolve_links_route():
    try:
        init_db()
        payload = request.get_json(silent=True) or {}
        links = payload.get("links")

        if not isinstance(links, list) or len(links) == 0:
            return jsonify({"error": "No links provided"}), 400

        results = []
        for item in links[:MAX_LINKS_PER_REQUEST]:
            if str(item or "").strip():
                results.append(process_single_link(str(item)))

        if not results:
            return jsonify({"error": "No valid links provided"}), 400

        return jsonify({"results": results})
    except Exception as exc:
        return jsonify({"error": f"Server error: {str(exc)}"}), 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
                    
