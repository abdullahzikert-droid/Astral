"""image_scanner.py — scan images in LLM requests for PII/secrets with Presidio.

Pipeline (same idea as presidio-image-redactor, but run through the *same*
PresidioDLPEngine as text, so policy, thresholds, custom/admin recognizers,
deny-list, context enhancer, proof and prompt-injection phrases all apply):

  image bytes -> OCR (tesseract, word boxes) -> text + word offsets
              -> dlp.scan_ex(text)  -> hits + RecognizerResults
              -> span -> word boxes -> black-box redaction (pixels)

Actions: block -> whole request 403s | redact -> boxes painted, image bytes
replaced in the body | warn -> reported only.  Fail-safe: if a span can't be
mapped to a box the hit is upgraded to block rather than leaking.

Env: APEXION_IMAGE_SCAN=1|0  APEXION_IMAGE_FAIL_MODE=open|closed
     APEXION_IMAGE_MAX_BYTES  APEXION_IMAGE_MAX_COUNT  APEXION_OCR_MIN_CONF
     APEXION_OCR_PSM  APEXION_OCR_LANG  APEXION_OCR_TIMEOUT
Needs: pip install pytesseract Pillow  +  the `tesseract` binary.
Not covered: remote image URLs (not fetched), animated frames > 0, PDFs.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Optional

ENABLED = os.environ.get("APEXION_IMAGE_SCAN", "1").lower() not in ("0", "false", "no", "off")
FAIL_CLOSED = os.environ.get("APEXION_IMAGE_FAIL_MODE", "open").lower() == "closed"
MAX_BYTES = int(os.environ.get("APEXION_IMAGE_MAX_BYTES", 10 * 1024 * 1024))
MAX_COUNT = int(os.environ.get("APEXION_IMAGE_MAX_COUNT", 10))
MIN_CONF = float(os.environ.get("APEXION_OCR_MIN_CONF", 30))
PSM = os.environ.get("APEXION_OCR_PSM", "3")
LANG = os.environ.get("APEXION_OCR_LANG", "eng")
TIMEOUT = int(os.environ.get("APEXION_OCR_TIMEOUT", 30))
PAD = 3
DEBUG = os.environ.get("APEXION_IMAGE_DEBUG", "").lower() in ("1", "true", "yes", "on")
_MIME = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp", "GIF": "image/gif"}
_DATA_URI = re.compile(r"^data:(image/[\w.+-]+);base64,(.*)$", re.S)


@lru_cache(maxsize=1)
def available() -> tuple[bool, str]:
    try:
        import pytesseract
        from PIL import Image  # noqa: F401
        pytesseract.get_tesseract_version()
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:160]


# ── locating images inside request bodies ────────────────────────────────────
@dataclass
class ImageRef:
    raw: bytes
    sha: str
    set_bytes: Callable[[bytes, str], None]


def _b64d(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return None


def _mk(raw: bytes, setter) -> ImageRef:
    return ImageRef(raw, hashlib.sha256(raw).hexdigest(), setter)


def find_images(node) -> tuple[list[ImageRef], int]:
    """Walk any provider body; return (inline image refs, remote-URL image count).
    Covers Anthropic (source.base64), OpenAI chat/responses (image_url data: URI),
    Google (inlineData/inline_data). Setters mutate the block in place."""
    refs: list[ImageRef] = []
    remote = [0]

    def walk(n):
        if isinstance(n, list):
            for x in n:
                walk(x)
            return
        if not isinstance(n, dict):
            return
        t, src = n.get("type"), n.get("source")
        if t == "image" and isinstance(src, dict):
            if src.get("type") == "base64" and isinstance(src.get("data"), str):
                raw = _b64d(src["data"])
                if raw is not None:
                    def s(b, m, src=src):
                        src["data"] = base64.b64encode(b).decode(); src["media_type"] = m
                    refs.append(_mk(raw, s))
            else:
                remote[0] += 1
            return
        if t in ("image_url", "input_image"):
            iu = n.get("image_url")
            holder, key = (n, "image_url") if isinstance(iu, str) else ((iu, "url") if isinstance(iu, dict) else (None, None))
            url = holder.get(key) if holder else None
            m = _DATA_URI.match(url) if isinstance(url, str) else None
            if m and _b64d(m.group(2)) is not None:
                def s(b, mime, h=holder, k=key):
                    h[k] = f"data:{mime};base64,{base64.b64encode(b).decode()}"
                refs.append(_mk(_b64d(m.group(2)), s))
            elif url:
                remote[0] += 1
            return
        for k in ("inlineData", "inline_data"):
            d = n.get(k)
            if not isinstance(d, dict):
                continue
            mt = d.get("mimeType") or d.get("mime_type") or ""
            if mt.startswith("image/") and isinstance(d.get("data"), str):
                raw = _b64d(d["data"])
                if raw is not None:
                    def s(b, mime, d=d):
                        d["data"] = base64.b64encode(b).decode()
                        for mk in ("mimeType", "mime_type"):
                            if mk in d:
                                d[mk] = mime
                    refs.append(_mk(raw, s))
                return
        for v in n.values():
            if isinstance(v, (dict, list)):
                walk(v)

    walk(node)
    return refs, remote[0]


def multipart_parts(content_type: str, body: bytes) -> list[bytes]:
    """Exact (byte-for-byte) part bodies of a multipart/form-data payload.
    mitmproxy's multipart_form is lossy for binary data (it mangles CR/LF), so
    we split on the boundary ourselves."""
    m = re.search(r'boundary="?([^";\s]+)"?', content_type, re.I)
    if not m:
        return []
    delim = b"--" + m.group(1).encode()
    out = []
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        out.append(data[:-2] if data.endswith(b"\r\n") else data)
    return out


_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")


def sniff_image(raw: bytes) -> bool:
    """True if `raw` is a decodable image (cheap magic check first)."""
    if len(raw) < 64:
        return False
    if not (raw.startswith(_MAGIC) or (raw[:4] == b"RIFF" and raw[8:12] == b"WEBP")):
        return False
    try:
        from PIL import Image
        Image.open(io.BytesIO(raw)).verify()
        return True
    except Exception:
        return False


# ── OCR / redaction primitives ───────────────────────────────────────────────
@dataclass
class _Word:
    start: int
    end: int
    box: tuple
    line: int


def _load(raw: bytes):
    from PIL import Image, ImageOps
    Image.MAX_IMAGE_PIXELS = 80_000_000
    img = Image.open(io.BytesIO(raw))
    fmt = img.format
    img.load()
    return ImageOps.exif_transpose(img), fmt


def _ocr(img) -> tuple[str, list[_Word]]:
    import pytesseract
    from PIL import Image, ImageOps, ImageStat
    if img.mode in ("RGBA", "LA", "P"):
        rgba = img.convert("RGBA")
        bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(bg, rgba)
    g = ImageOps.autocontrast(img.convert("L"))
    if ImageStat.Stat(g).mean[0] < 110:          # dark-mode screenshots
        g = ImageOps.invert(g)
    w, h = g.size
    m = max(w, h)   # small UI text needs ~3000px long side for tesseract; cap huge images at 4000
    scale = 4000 / m if m > 4000 else min(3.0, 3000 / m) if m < 3000 else 1.0
    if scale != 1.0:
        g = g.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
    d = pytesseract.image_to_data(g, lang=LANG, config=f"--psm {PSM}",
                                  output_type=pytesseract.Output.DICT, timeout=TIMEOUT)
    lines: dict[tuple, list] = {}
    for i, t in enumerate(d["text"]):
        t = (t or "").strip()
        try:
            conf = float(d["conf"][i])
        except (TypeError, ValueError):
            conf = -1
        if not t or conf < MIN_CONF:
            continue
        l, tp, wd, ht = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
        box = (l / scale, tp / scale, (l + wd) / scale, (tp + ht) / scale)
        lines.setdefault((d["block_num"][i], d["par_num"][i], d["line_num"][i]), []).append((t, box))
    parts, words, pos = [], [], 0
    for li, ws in enumerate(lines.values()):
        for j, (t, box) in enumerate(ws):
            if j:
                parts.append(" "); pos += 1
            words.append(_Word(pos, pos + len(t), box, li))
            parts.append(t); pos += len(t)
        parts.append("\n"); pos += 1
    return "".join(parts), words


def _boxes_for(words: list[_Word], start: int, end: int) -> list[tuple]:
    by_line: dict[int, list] = {}
    for w in words:
        if w.start < end and w.end > start:
            by_line.setdefault(w.line, []).append(w.box)
    return [(min(b[0] for b in bs), min(b[1] for b in bs), max(b[2] for b in bs), max(b[3] for b in bs))
            for bs in by_line.values()]


def _redact(raw: bytes, boxes: list[tuple]) -> tuple[bytes, str]:
    from PIL import ImageDraw
    img, fmt = _load(raw)
    out_fmt = fmt if fmt in _MIME else "PNG"
    img = img.convert("RGB") if out_fmt == "JPEG" or img.mode not in ("RGBA", "LA", "P") else img.convert("RGBA")
    dr = ImageDraw.Draw(img)
    for l, t, r, b in boxes:
        dr.rectangle([l - PAD, t - PAD, r + PAD, b + PAD], fill=(0, 0, 0))
    buf = io.BytesIO()
    kw = {"quality": 95} if out_fmt == "JPEG" else ({"lossless": True} if out_fmt == "WEBP" else {})
    img.save(buf, out_fmt, **kw)                 # re-encode also strips EXIF/metadata
    return buf.getvalue(), _MIME[out_fmt]


# ── scanner ──────────────────────────────────────────────────────────────────
@dataclass
class ImageScan:
    text: str = ""
    hits: list = field(default_factory=list)
    boxes: list = field(default_factory=list)
    redacted: Optional[tuple] = None             # (bytes, mime)


@dataclass
class ImageBatch:
    hits: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    scans: dict = field(default_factory=dict)    # sha -> ImageScan
    ocr: list = field(default_factory=list)
    count: int = 0
    ms: float = 0.0

    @property
    def active(self) -> bool:
        return bool(self.count or self.problems)

    @property
    def ocr_text(self) -> str:
        return "\n".join(self.ocr)

    def report_suffix(self) -> str:
        return "".join(f"\n\n[image {i} OCR]\n{t}" for i, t in enumerate(self.ocr, 1))

    def apply(self, body) -> tuple[object, int]:
        """Swap redacted pixels into `body` (re-walks it, so it works on the
        post-text-redaction copy). Returns (body, images_changed)."""
        n = 0
        for ref in find_images(body)[0]:
            sc = self.scans.get(ref.sha)
            if sc and sc.redacted:
                ref.set_bytes(*sc.redacted); n += 1
        return body, n


def _sys_hit(action: str, severity: str, label: str) -> dict:
    return {"id": "IMAGE_SCAN", "label": label, "category": "image_scan", "severity": severity,
            "action": action, "score": 1.0,
            "proof": {"engine": "image", "layer": "Image OCR (tesseract)", "recognizer": "image_scan",
                      "explanation": label, "stages": ["image OCR"], "score": 1.0}}


class ImageScanner:
    def __init__(self, dlp, custom=None):
        self.dlp, self.custom = dlp, custom
        self._cache: "OrderedDict[str, ImageScan]" = OrderedDict()
        ok, why = available()
        print(f"[Apexion] image scanning: {'ON (tesseract OCR + Presidio)' if ok else 'UNAVAILABLE — ' + why}"
              f" | fail-mode={'closed' if FAIL_CLOSED else 'open'}")

    def _scan_one(self, ref: ImageRef) -> ImageScan:
        if ref.sha in self._cache:
            self._cache.move_to_end(ref.sha)
            return self._cache[ref.sha]
        img, _ = _load(ref.raw)
        text, words = _ocr(img)
        sc = ImageScan(text=text)
        if text.strip():
            hits, results = self.dlp.scan_ex(text)
            if self.custom is not None:
                ch, _unc = self.custom.scan_hits(text)
                for h in ch:                      # no span info -> can't box -> fail safe
                    if h["action"] == "redact":
                        h["action"] = "block"
                        h.setdefault("proof", {}).setdefault("stages", []).append(
                            "custom detector hit in image: no span to redact, blocking")
                hits += ch
            by_id = {h["id"]: h for h in hits}
            for r in self.dlp.enforced(results):
                bx = _boxes_for(words, r.start, r.end)
                sc.boxes += bx
                h = by_id.get(r.entity_type)
                if not bx and h is not None:
                    h["action"] = "block"
                    h["proof"]["stages"].append("no OCR word box for span: cannot redact image, blocking")
            for h in hits:
                pr = h.setdefault("proof", {})
                pr["source"] = "image"
                pr.setdefault("stages", []).insert(0, "image OCR: tesseract")
            sc.hits = hits
            if sc.boxes:
                sc.redacted = _redact(ref.raw, sc.boxes)
        self._cache[ref.sha] = sc
        while len(self._cache) > 32:
            self._cache.popitem(last=False)
        return sc

    def _scan_refs(self, refs: list[ImageRef], remote: int = 0) -> ImageBatch:
        b = ImageBatch()
        if not ENABLED:
            return b
        t0 = time.perf_counter()
        if remote:
            print(f"[Apexion] {remote} remote-URL image(s) not fetched — not scanned")
        ok, why = available()
        problems: list[str] = []
        seen: set = set()
        for ref in refs:
            if ref.sha in seen:
                continue
            seen.add(ref.sha)
            b.count += 1
            if b.count > MAX_COUNT:
                problems.append(f"more than {MAX_COUNT} images"); break
            if len(ref.raw) > MAX_BYTES:
                problems.append(f"image over {MAX_BYTES // 1048576} MB"); continue
            if not ok:
                problems.append(f"OCR unavailable ({why})"); break
            try:
                sc = self._scan_one(ref)
            except Exception as e:
                problems.append(f"{type(e).__name__}: {str(e)[:100]}"); continue
            b.scans[ref.sha] = sc
            idx = len(b.scans)
            if DEBUG:
                print(f"[Apexion][img-debug] OCR {len(sc.text)} chars, {len(sc.boxes)} redact boxes:\n"
                      f"{sc.text[:600]}\n[Apexion][img-debug] hits={[(h['id'], h['action'], h.get('score')) for h in sc.hits]}")
            if sc.text.strip():
                b.ocr.append(sc.text.strip())
            for h in copy.deepcopy(sc.hits):
                h["label"] = f"{h['label']} (in image {idx})"
                h["proof"]["image_index"] = idx
                b.hits.append(h)
        b.ms = round((time.perf_counter() - t0) * 1000)
        print(f"[Apexion] image scan: {b.count} image(s), {sum(len(x) for x in b.ocr)} OCR chars, "
              f"{len(b.hits)} hit(s), {b.ms} ms")
        if problems:
            b.problems = problems
            msg = f"{len(problems)} image(s) could not be scanned: {'; '.join(sorted(set(problems)))[:200]}"
            print(f"[Apexion] {msg}")
            b.hits.append(_sys_hit("block" if FAIL_CLOSED else "warn", "high" if FAIL_CLOSED else "medium", msg))
        return b

    def scan_body(self, body) -> ImageBatch:
        refs, remote = find_images(body)
        return self._scan_refs(refs, remote)

    def scan_raw(self, blobs: list[bytes]) -> ImageBatch:
        return self._scan_refs([_mk(r, lambda *_: None) for r in blobs])
