import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get("LINK_CACHE_DB", "link_cache.db")
CACHE_TTL_SECONDS = 86400
MAX_LINKS_PER_REQUEST = 15
MAX_REDIRECT_HOPS = 12
REQUEST_TIMEOUT_SECONDS = 9

PARAM_KEYS = [
    "url", "target", "dest", "destination", "redirect",
    "redirect_url", "return", "return_url", "next", "u", "to",
    "link", "r", "q", "data", "href", "go", "out", "uri", "callback",
    "continue", "forward", "ref", "site", "endpoint", "step", "location",
    "key", "token", "unlock", "final", "dl", "download", "bypass"
]

AD_OR_CHECKPOINT_HINTS = (
    "ad", "ads", "advert", "banner", "pop", "interstitial", "gate",
    "checkpoint", "verify", "verification", "captcha", "turnstile",
    "timer", "countdown", "wait", "key", "loot", "linkvertise", "work.ink"
)

CHALLENGE_MARKERS = (
    "cf-browser-verification",
    "challenge-platform",
    "cdn-cgi/challenge-platform",
    "h-captcha",
    "hcaptcha",
    "g-recaptcha",
    "recaptcha",
    "cf-turnstile",
    "just a moment...",
    "checking your browser",
    "enable javascript and cookies",
    "access denied",
)

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


def log_info(msg: str) -> None:
    print(f"[RESOLVER] {msg}", flush=True)


def init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS resolved_links (
                    source_url TEXT PRIMARY KEY,
                    resolved_url TEXT NOT NULL,
                    meta_json TEXT,
                    created_at INTEGER NOT NULL
                )
                """
            )
            cols = [r[1] for r in conn.execute("PRAGMA table_info(resolved_links)").fetchall()]
            if "meta_json" not in cols:
                conn.execute("ALTER TABLE resolved_links ADD COLUMN meta_json TEXT")
            conn.commit()
    except Exception as exc:
        log_info(f"DB init warning: {exc}")


init_db()


def get_cached_entry(source_url: str):
    try:
        now = int(time.time())
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            row = conn.execute(
                "SELECT resolved_url, meta_json, created_at FROM resolved_links WHERE source_url = ?",
                (source_url,),
            ).fetchone()
            if row and (now - int(row[2])) < CACHE_TTL_SECONDS:
                meta = {}
                if row[1]:
                    try:
                        meta = json.loads(row[1])
                    except Exception:
                        meta = {}
                return {
                    "resolvedUrl": row[0],
                    "reason": meta.get("reason", "cache_hit"),
                    "gateType": meta.get("gateType", "none"),
                    "stepCount": int(meta.get("stepCount", 1)),
                    "steps": meta.get("steps", []),
                }
    except Exception as exc:
        log_info(f"Cache read warning: {exc}")
    return None


def save_cached_entry(source_url: str, resolved_url: str, payload_meta: dict) -> None:
    try:
        now = int(time.time())
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute(
                """
                INSERT INTO resolved_links (source_url, resolved_url, meta_json, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_url) DO UPDATE SET
                    resolved_url = excluded.resolved_url,
                    meta_json = excluded.meta_json,
                    created_at = excluded.created_at
                """,
                (source_url, resolved_url, json.dumps(payload_meta), now),
            )
            conn.commit()
    except Exception as exc:
        log_info(f"Cache write warning: {exc}")


def is_private_or_disallowed_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True

def is_safe_remote_host(host: str) -> bool:
    clean_host = (host or "").strip().lower().rstrip(".")
    if not clean_host or "." not in clean_host or clean_host in BLOCKED_HOSTS:
        return False

    try:
        if is_private_or_disallowed_ip(clean_host):
            return False
    except Exception:
        pass

    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        for info in addr_info:
            sockaddr = info[4]
            if sockaddr and is_private_or_disallowed_ip(sockaddr[0]):
                return False
    except Exception:
        return False

    return True


def is_valid_http_url(url: str) -> bool:
    try:
        if not url or len(url) > 4096:
            return False
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").strip().lower()
        if parsed.scheme not in ("http", "https") or not host:
            return False
        return is_safe_remote_host(host)
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


def looks_like_ad_or_tracker(url: str) -> bool:
    low = (url or "").lower()
    return any(hint in low for hint in AD_OR_CHECKPOINT_HINTS)


def detect_page_gate_type(html_text: str) -> str:
    if not html_text:
        return "none"
    low = html_text.lower()
    if any(marker in low for marker in CHALLENGE_MARKERS):
        return "bot_challenge_or_captcha"
    if any(k in low for k in ("verify", "verification", "task", "complete", "subscribe", "discord", "key")):
        return "verification_task_gate"
    if "countdown" in low or "settimeout" in low or "setinterval" in low:
        return "js_or_timer_gate"
    if looks_like_ad_or_tracker(low):
        return "ad_gate"
    return "none"


def extract_from_string_blob(blob: str, base_url: str = ""):
    if not blob:
        return None

    direct_matches = re.findall(r'https?://[^\s"\'<>\\)\]}]+', blob)
    non_ad_candidates = []
    ad_candidates = []

    for raw_match in direct_matches:
        cleaned = raw_match.rstrip(".,;:")
        if is_valid_http_url(cleaned):
            if looks_like_ad_or_tracker(cleaned):
                ad_candidates.append(cleaned)
            else:
                non_ad_candidates.append(cleaned)

    if non_ad_candidates:
        return non_ad_candidates[0]

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
            if any(
                k in rel.lower()
                for k in ("redirect", "target", "dest", "next", "goto", "go", "out", "key", "auth", "step", "unlock")
            ):
                full_rel = urljoin(base_url, rel)
                if is_valid_http_url(full_rel):
                    return full_rel

    return ad_candidates[0] if ad_candidates else None


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
    except Exception as exc:
        log_info(f"Embedded target warning: {exc}")
        return current, reason
    return current, reason


def extract_html_or_js_target(base_url: str, html_text: str):
    if not html_text:
        return None, None
    snippet = html_text[:196608]

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
        r'(?:redirectUrl|targetUrl|destinationUrl|nextUrl|redirect_url|target_url|next_step|finalUrl|unlockUrl)\s*[:=]\s*["\']([^"\']+)["\']',
        r'atob\(\s*["\']([A-Za-z0-9+/=_-]{8,1024})["\']\s*\)',
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

    cta_matches = re.findall(
        r'<(?:a|form)[^>]*(?:href|action)=["\']([^"\']+)["\'][^>]*>(.*?)</(?:a|form)>',
        snippet,
        re.IGNORECASE | re.DOTALL,
    )
    for raw_href, inner_html in cta_matches:
        clean_text = re.sub(r"<[^>]+>", " ", inner_html).lower()
        href_low = raw_href.lower()
        if any(
            k in clean_text or k in href_low
            for k in ("continue", "get key", "unlock", "proceed", "next", "destination", "target", "verify", "complete")
        ):
            candidate = urljoin(base_url, unquote(raw_href.strip()))
            if is_valid_http_url(candidate) and not looks_like_ad_or_tracker(candidate):
                return candidate, "cta_link"

    return None, None


def append_step(steps: list, title: str, url: str, status: str, gate_type: str = "none") -> None:
    steps.append({
        "step": len(steps) + 1,
        "title": title,
        "url": url,
        "status": status,
        "gateType": gate_type,
    })


def follow_server_redirects(url: str):
    steps = []
    current, reason = extract_embedded_target(url)
    append_step(
        steps,
        "Initial / Embedded Target Check",
        current,
        "bypassed_or_extracted" if current != url else "inspected",
        "ad_gate" if looks_like_ad_or_tracker(current) else "none",
    )

    visited = {current}
    detected_gate = "ad_gate" if looks_like_ad_or_tracker(current) else "none"
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)

    try:
        for _ in range(MAX_REDIRECT_HOPS):
            current, emb_reason = extract_embedded_target(current)
            if emb_reason != "direct":
                reason = emb_reason

            if not is_valid_http_url(current):
                reason = "blocked_or_invalid_hop"
                append_step(steps, "Host Validation", current, "blocked", "blocked_or_invalid_hop")
                break

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
                for hop_resp in resp.history:
                    if is_valid_http_url(hop_resp.url):
                        append_step(
                            steps,
                            f"HTTP Redirect ({hop_resp.status_code})",
                            hop_resp.url,
                            "skipped_redirect",
                            "ad_gate" if looks_like_ad_or_tracker(hop_resp.url) else "none",
                        )

            if resp.status_code in (401, 403, 429, 503):
                log_info(f"HTTP status {resp.status_code} at {current}")
                resp.close()
                reason = f"http_{resp.status_code}"
                detected_gate = f"http_{resp.status_code}"
                append_step(steps, f"HTTP {resp.status_code} Gate", current, "blocked_or_gated", detected_gate)
                break

            final_url = resp.url if is_valid_http_url(resp.url) else current
            final_url, post_reason = extract_embedded_target(final_url)
            if post_reason != "direct":
                reason = post_reason

            content_type = resp.headers.get("Content-Type", "").lower()
            next_url = None
            next_reason = None
            page_gate = "none"

            if (
            "text/html" in content_type
                or "application/xhtml" in content_type
                or "application/json" in content_type
            ):
                body_text = resp.content[:196608].decode(resp.encoding or "utf-8", errors="ignore")
                if "application/json" in content_type or body_text.lstrip().startswith(("{", "[")):
                    try:
                        parsed_json = json.loads(body_text)
                        next_url = find_url_in_object(parsed_json)
                        if next_url:
                            next_reason = "json_target"
                    except Exception:
                        next_url, next_reason = extract_html_or_js_target(final_url, body_text)
                        page_gate = detect_page_gate_type(body_text)
                else:
                    next_url, next_reason = extract_html_or_js_target(final_url, body_text)
                    page_gate = detect_page_gate_type(body_text)

            resp.close()

            if page_gate != "none":
                detected_gate = page_gate

            if next_url and is_valid_http_url(next_url) and next_url not in visited:
                visited.add(next_url)
                current = next_url
                reason = next_reason or "chained"
                append_step(
                    steps,
                    f"Extracted Next Target ({reason})",
                    current,
                    "attempted_bypass",
                    page_gate,
                )
            else:
                current = final_url
                if page_gate != "none" and reason in ("direct", "unchanged", "http_redirect"):
                    reason = page_gate
                append_step(
                    steps,
                    "Final Reached URL",
                    current,
                    "gated_or_stopped" if page_gate != "none" else "reached",
                    page_gate,
                )
                break
    except Exception as exc:
        log_info(f"Redirect error for {current}: {exc}")
        fallback_url, fallback_reason = extract_embedded_target(current)
        append_step(steps, "Fallback Recovery", fallback_url, "fallback", detected_gate)
        return fallback_url, (fallback_reason if fallback_reason != "direct" else "fallback"), detected_gate, steps
    finally:
        try:
            session.close()
        except Exception:
            pass

    return current, reason, detected_gate, steps


def process_single_link(raw_link: str) -> dict:
    clean_url = normalize_input_url(raw_link)
    if not clean_url:
        fallback = str(raw_link or "").strip()
        log_info(f"Invalid input: {fallback[:80]}")
        return {
            "resolvedUrl": fallback,
            "cached": False,
            "reason": "invalid_input",
            "gateType": "none",
            "stepCount": 0,
            "steps": [],
        }

    cached = get_cached_entry(clean_url)
    if cached:
        log_info(f"Cache hit: {clean_url[:80]} -> {cached['resolvedUrl'][:80]}")
        return {
            "resolvedUrl": cached["resolvedUrl"],
            "cached": True,
            "reason": "cache_hit",
            "gateType": cached["gateType"],
            "stepCount": cached["stepCount"],
            "steps": cached["steps"],
        }

    resolved, reason, gate_type, steps = follow_server_redirects(clean_url)
    if not is_valid_http_url(resolved):
        resolved = clean_url
        reason = "unchanged"
    elif resolved == clean_url and reason == "direct":
        reason = "unchanged"

    step_count = len(steps)
    log_info(f"Resolved ({reason}, gate={gate_type}, steps={step_count}): {clean_url[:80]} -> {resolved[:80]}")
    save_cached_entry(clean_url, resolved, {
        "reason": reason,
        "gateType": gate_type,
        "stepCount": step_count,
        "steps": steps,
    })
    return {
        "resolvedUrl": resolved,
        "cached": False,
        "reason": reason,
        "gateType": gate_type,
        "stepCount": step_count,
        "steps": steps,
    }


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
        log_info(f"Route error: {exc}")
        return jsonify({"error": f"Server error: {str(exc)}"}), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
