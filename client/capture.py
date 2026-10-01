"""capture.py — privacy-safe traffic capture to learn how attachments are sent.

Enable:  APEXION_CAPTURE=1 ./start.sh      (or APEXION_CAPTURE=all to include noise)
Output:  captures/capture-<timestamp>.jsonl   (one JSON record per request)

Only AI-related hosts are recorded; noise (telemetry, static assets, GET page
loads) is dropped. Nothing sensitive is stored: no cookies/auth headers, no
query values, no body text, no image bytes. Strings become {len, prefix<=24},
base64/data-URIs are flagged with their decoded size, multipart parts keep
headers + size + image sniff. Send me the .jsonl after attaching an image in
each UI you care about (Claude, ChatGPT, Gemini...).
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Optional

import image_scanner

MODE = os.environ.get("APEXION_CAPTURE", "").lower()
ENABLED = MODE not in ("", "0", "false", "off", "no")
ALL = MODE == "all"
OUT = Path(__file__).parent / "captures" / f"capture-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
_lock = threading.Lock()

_NOISE_PATH = re.compile(
    r"(/ces/|/rgstr|/sentry|/statsig|/segment|/analytics|/telemetry|/collect|/metrics|/track|/log(?:s|ging)?(?:/|$|\?)|"
    r"/cdn-cgi/|/beacon|/pixel|/ping|/heartbeat|/gen_204|/_next/|/assets/|\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|map|json)(?:\?|$))", re.I)
_NOISE_HOST = re.compile(r"(sentry|statsig|segment|datadog|intercom|doubleclick|googletagmanager|google-analytics|"
                         r"cloudflareinsights|featuregates|browser-intake|clarity\.ms)", re.I)
_KEEP_HDR = re.compile(r"^(content-type|content-length|content-encoding|content-disposition|accept|origin|referer|"
                       r"x-ms-.*|x-goog-.*|x-amz-.*|x-upload-.*|x-file-.*|upload-.*|tus-.*|range|content-range|"
                       r"x-request-id|anthropic-.*|openai-.*|oai-.*|x-app|x-client.*)$", re.I)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_LONG = re.compile(r"[A-Za-z0-9_\-]{24,}")


def relevant(host: str, method: str, path: str, ct: str, is_ai_host: bool) -> bool:
    if not is_ai_host or (_NOISE_HOST.search(host) and not ALL):
        return False
    if ALL:
        return True
    if method in ("POST", "PUT", "PATCH"):
        return not _NOISE_PATH.search(path.split("?")[0]) or ct.startswith(("image/", "multipart/"))
    return False


def _norm_path(path: str) -> str:
    base, _, q = path.partition("?")
    base = _LONG.sub("<id>", _UUID.sub("<uuid>", base))
    keys = sorted({kv.split("=")[0] for kv in q.split("&") if kv})
    return base + (("?" + ",".join(keys)) if keys else "")


def _hdrs(h) -> dict:
    return {k.lower(): (v[:120]) for k, v in h.items() if _KEEP_HDR.match(k)}


def _str(s: str) -> dict:
    d: dict = {"len": len(s)}
    if len(s) <= 40 and re.fullmatch(r"[\w./:\-]+", s):   # ids / enums only — never free text
        d["val"] = s
    m = re.match(r"^data:([\w/+.-]+);base64,(.*)$", s, re.S)
    b64 = m.group(2) if m else (s if len(s) > 200 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", s[:400] or "x") else None)
    if b64:
        try:
            raw = base64.b64decode(b64, validate=False)
            d = {"base64": True, "decoded_bytes": len(raw), "data_uri_mime": m.group(1) if m else None,
                 "is_image": image_scanner.sniff_image(raw)}
        except Exception:
            pass
    return d


def skeleton(o, depth=0):
    if depth > 8:
        return "…"
    if isinstance(o, dict):
        return {k: skeleton(v, depth + 1) for k, v in list(o.items())[:40]}
    if isinstance(o, list):
        return [skeleton(v, depth + 1) for v in o[:4]] + ([f"…(+{len(o) - 4})"] if len(o) > 4 else [])
    if isinstance(o, str):
        return _str(o)
    return o


def _body(headers, content: bytes) -> dict:
    ct = headers.get("content-type", "").lower()
    out: dict = {"size": len(content or b"")}
    if not content:
        return out
    if "multipart/" in ct:
        parts = []
        m = re.search(r'boundary="?([^";\s]+)"?', headers.get("content-type", ""), re.I)
        if m:
            for chunk in content.split(b"--" + m.group(1).encode())[1:]:
                if chunk.startswith(b"--"):
                    break
                head, _, data = chunk.partition(b"\r\n\r\n")
                parts.append({"headers": re.sub(r'filename="[^"]*?(\.\w{1,5})?"', r'filename="<name>\1"', head.decode("latin1").strip().replace("\r\n", " | ")[:200]),
                              "size": len(data), "is_image": image_scanner.sniff_image(data[:-2] if data.endswith(b"\r\n") else data)})
        out["multipart_parts"] = parts
    elif "json" in ct or content[:1] in (b"{", b"["):
        try:
            out["json"] = skeleton(json.loads(content))
        except Exception:
            out["json_error"] = True
    elif "x-www-form-urlencoded" in ct and not image_scanner.sniff_image(content):
        out["form_keys"] = sorted({kv.split(b"=")[0].decode("latin1")[:30] for kv in content.split(b"&")})[:20]
    else:
        out["raw_is_image"] = image_scanner.sniff_image(content)
        out["magic"] = content[:8].hex()
    return out


def record(flow, is_ai_host: bool, meta: Optional[dict] = None) -> None:
    if not ENABLED:
        return
    rq = flow.request
    ct = rq.headers.get("content-type", "").lower()
    if not relevant(rq.pretty_host, rq.method, rq.path, ct, is_ai_host):
        return
    rs = flow.response
    rec = {
        "t": round(time.time(), 2), "method": rq.method, "host": rq.pretty_host, "path": _norm_path(rq.path),
        "http": rq.http_version, "req_headers": _hdrs(rq.headers), "req": _body(rq.headers, rq.raw_content and rq.content),
        "resp": None,
        "apexion": (meta or {}),
    }
    if rs is not None:
        streamed = bool(getattr(rs, "stream", False))
        rec["resp"] = {"status": rs.status_code, "headers": _hdrs(rs.headers), "streamed": streamed}
        if not streamed and rs.content and len(rs.content) < 200_000:
            rec["resp"]["body"] = _body(rs.headers, rs.content)
        if rs.headers.get("x-apexion-action"):
            rec["resp"]["apexion_action"] = rs.headers["x-apexion-action"]
    with _lock:
        OUT.parent.mkdir(exist_ok=True)
        with OUT.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    img = "IMAGE" if (rec["req"].get("raw_is_image") or any(p.get("is_image") for p in rec["req"].get("multipart_parts", []))
                      or "is_image\": true" in json.dumps(rec["req"])) else ""
    print(f"[CAPTURE] {rq.method} {rq.pretty_host}{rec['path'][:70]} ct={ct[:32]} req={rec['req']['size']}B "
          f"{img} -> {rs.status_code if rs is not None else '-'}")
