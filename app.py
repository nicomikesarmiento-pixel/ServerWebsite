import base64
import binascii
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
MAX_REDIRECT_HOPS = 10
REQUEST_TIMEOUT_SECONDS = 9

PARAM_KEYS = [
    "url", "target", "dest", "destination", "redirect",
    "redirect_url", "return", "return_url", "next", "u", "to",
    "link", "r", "q", "data", "href", "go", "out", "uri", "callback",
    "continue", "forward", "ref", "site", "endpoint", "step", "location"
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive",
}

BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "serverwebsite-3wvl.onrender.com",
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


def is_valid_http_url(url: str) -> bool:
    try:
        if not url or len(url) > 4096:
            return False
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").strip().lower()
        if parsed.scheme not in ("http", "https") or not host:
            return False
        if host in BLOCKED_HOSTS or "." not in host:
            return False
        return True
    except Exception:
        return False


def normalize_input_url(raw_value: str):
    candidate = str(raw_value or "").strip()
    if not candidate or len(candidate) > 4096:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate
    return candidate if is_valid_http_url(candidate) else None


def try_decode_hex(token: str):
    cleaned = str(token or "").strip()
    if len(cleaned) < 16 or len(cleaned) > 4096 or len(cleaned) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    try:
        decoded = binascii.unhexlify(cleaned).decode("utf-8", errors="ignore").strip()
        if is_valid_http_url(decoded):
            return decoded
    except Exception:
        return None
    return None


def try_decode_base64(token: str):
    cleaned = str(token or "").strip()
    if not cleaned or len(cleaned) < 8 or len(cleaned) > 4096:
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
        return try_decode_base64(val) or try_decode_hex(val)
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


def extract_from_string_blob(blob: str, base_url: str = ""):
    if not blob:
        return None

    direct_matches = re.findall(r'https?://[^\s"\'<>\\)\]}]+', blob)
    for raw_match in direct_matches:
        cleaned = raw_match.rstrip(".,;:")
        if is_valid_http_url(cleaned):
            return cleaned

    for token in re.findall(r"[A-Za-z0-9+/_=-]{12,1024}", blob):
        b64 = try_decode_base64(token)
        if b64:
            return b64
        hx = try_decode_hex(token)
        if hx:
            return hx

    if base_url:
        rel_matches = re.findall(r'["\'](/[^"\'\s<>]{2,512})["\']', blob)
        for rel in rel_matches:
            if any(k in rel.lower() for k in ("redirect", "target", "dest", "next", "goto", "go", "out", "key", "auth", "step")):
                full_rel = urljoin(base_url, rel)
                if is_valid_http_url(full_rel):
                    return full_rel

    return None


def extract_embedded_target(url: str):
    current = url
    reason = "direct"
    try:
        for _ in range(6):
            parsed = urlparse(current)
            found = None
            found_reason = None

            combined_parts = []
            qs = parse_qs(parsed.query, keep_blank_values=False)
            for key in PARAM_KEYS:
                if key in qs and qs[key]:
                    for v in qs[key]:
                        combined_parts.append((unquote(v).strip(), "query_param"))

            for _, vals in qs.items():
                for v in vals:
                    combined_parts.append((unquote(v).strip(), "query_value"))

            if parsed.fragment:
                combined_parts.append((unquote(parsed.fragment).strip(), "fragment"))
                frag_qs = parse_qs(parsed.fragment, keep_blank_values=False)
                for key in PARAM_KEYS:
                    if key in frag_qs and frag_qs[key]:
                        combined_parts.append((unquote(frag_qs[key][0]).strip(), "fragment_param"))

            for seg in parsed.path.split("/"):
                seg_dec = unquote(seg).strip()
                if seg_dec:
                    combined_parts.append((seg_dec, "path_segment"))

            for part, src_kind in combined_parts:
                if is_valid_http_url(part):
                    found = part
                    found_reason = src_kind
                    break
                if part.startswith("//"):
                    proto_url = "https:" + part
                    if is_valid_http_url(proto_url):
                        found = proto_url
                        found_reason = f"{src_kind}_proto"
                        break
                decoded_b64 = try_decode_base64(part)
                if decoded_b64:
                    found = decoded_b64
                    found_reason = f"{src_kind}_base64"
                    break
                decoded_hex = try_decode_hex(part)
                if decoded_hex:
                    found = decoded_hex
                    found_reason = f"{src_kind}_hex"
                    break
                blob_url = extract_from_string_blob(part, current)
                if blob_url:
                    found = blob_url
                    found_reason = f"{src_kind}_blob"
                    break

            if found and found != current and is_valid_http_url(found):
                current = found
                reason = found_reason or "extracted"
            else:
                break
    except Exception:
        return current, reason
    return current, reason


def extract_html_or_js_target(base_url: str, html_text: str):
    if not html_text:
        return None, None
    snippet = html_text[:131072]

    meta_match = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?[^"\']*url\s*=\s*([^"\'>\s;]+)',
        snippet,
        re.IGNORECASE,
    )
    if meta_match:
        candidate = urljoin(base_url, unquote(meta_match.group(1).strip()))
        if is_valid_http_url(candidate):
            return candidate, "meta_refresh"

    js_patterns = [
        r'(?:window\.location(?:\.href)?|location\.href|location\.replace|location\.assign)\s*=\s*["\']([^"\']+)["\']',
        r'(?:location\.replace|location\.assign|window\.open)\(\s*["\']([^"\']+)["\']',
        r'(?:redirectUrl|targetUrl|destinationUrl|nextUrl|redirect_url|target_url|next_step)\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    for pattern in js_patterns:
        match = re.search(pattern, snippet, re.IGNORECASE)
        if match:
            raw_target = unquote(match.group(1).strip())
            b64_inside = try_decode_base64(raw_target)
            if b64_inside:
                return b64_inside, "js_base64"
            candidate = urljoin(base_url, raw_target)
            if is_valid_http_url(candidate):
                return candidate, "js_redirect"

    return None, None


def follow_server_redirects(url: str):
    current, reason = extract_embedded_target(url)
    visited = {current}
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    try:
        for _ in range(MAX_REDIRECT_HOPS):
            current, emb_reason = extract_embedded_target(current)
            if emb_reason != "direct":
                reason = emb_reason

            step_headers = {"Referer": current}
            resp = session.get(
                current,
                headers=step_headers,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT_SECONDS,
                stream=True,
            )

            if resp.history:
                reason = "http_redirect"

            final_url = resp.url if is_valid_http_url(resp.url) else current
            final_url, post_reason = extract_embedded_target(final_url)
            if post_reason != "direct":
                reason = post_reason

            content_type = resp.headers.get("Content-Type", "").lower()
            next_url = None
            next_reason = None

            if "text/html" in content_type or "application/xhtml" in content_type or "application/json" in content_type:
                body_text = resp.content[:131072].decode(resp.encoding or "utf-8", errors="ignore")
                if "application/json" in content_type or body_text.lstrip().startswith(("{", "[")):
                    try:
                        parsed_json = json.loads(body_text)
                        next_url = find_url_in_object(parsed_json)
                        if next_url:
                            next_reason = "json_target"
                    except Exception:
                        next_url, next_reason = extract_html_or_js_target(final_url, body_text)
                else:
                    next_url, next_reason = extract_html_or_js_target(final_url, body_text)

            resp.close()

            if next_url and is_valid_http_url(next_url) and next_url not in visited:
                visited.add(next_url)
                current = next_url
                reason = next_reason or "chained"
            else:
                current = final_url
                break
    except Exception:
        fallback_url, fallback_reason = extract_embedded_target(current)
        return fallback_url, (fallback_reason if fallback_reason != "direct" else "fallback")
    finally:
        try:
            session.close()
        except Exception:
            pass

    return current, reason


def process_single_link(raw_link: str) -> dict:
    clean_url = normalize_input_url(raw_link)
    if not clean_url:
        fallback = str(raw_link or "").strip()
        return {"resolvedUrl": fallback, "cached": False, "reason": "invalid_input"}

    cached = get_cached_link(clean_url)
    if cached:
        return {"resolvedUrl": cached, "cached": True, "reason": "cache_hit"}

    resolved, reason = follow_server_redirects(clean_url)
    if not is_valid_http_url(resolved):
        resolved = clean_url
        reason = "unchanged"
    elif resolved == clean_url and reason == "direct":
        reason = "unchanged"

    save_cached_link(clean_url, resolved)
    return {"resolvedUrl": resolved, "cached": False, "reason": reason}


@app.route("/", methods=["GET"])
def index_route():
    return jsonify({
        "service": "Delta Link Resolver Engine",
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
                
