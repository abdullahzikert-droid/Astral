"""
apexion_addon.py — Apexion mitmproxy addon (no DB, no API server)

Actions per DLP hit (worst wins):
  warn   → pass request through, inject X-Apexion-Warning header into response
  redact → replace matched text with [REDACTED:<id>] in request body, forward cleaned
  block  → 403 immediately, request never reaches provider

Covers:
  api.anthropic.com                    CLAUDE_API
  claude.ai                            CLAUDE_WEB
  api.openai.com                       OPENAI_API
  chatgpt.com / chat.openai.com        CHATGPT_WEB  (incl. codex/*)
  generativelanguage.googleapis.com    GEMINI_API
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

import manager_client
import tool_scanner
import teach_client
import image_scanner
import capture
from presidio_engine import PresidioDLPEngine

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

DLP_POLICY_FILE    = Path(__file__).parent / ".policy_cache.json"
FALSE_FLAGS_FILE   = Path(__file__).parent / "false_flags.json"
ICON_FILE          = Path(__file__).parent / "apexion_icon.png"
# Per-model cache dir so switching APEXION_PI_MODEL doesn't reuse a stale
# folder from a previously downloaded model.
def _model_dir_for(name: str) -> Path:
    return Path(__file__).parent / "models" / name.replace("/", "_")
REPORT_SERVER_PORT = 8081

# Short-lived cache: notif_id -> full false-positive report payload. Populated
# right before each notify() call that includes a "Report false positive"
# button, looked up when that button is actually clicked (the OS only gives
# us back a small id/argument, not the original hit data). Entries are
# pruned after PENDING_REPORT_TTL so this can't grow unbounded.
PENDING_REPORTS: dict = {}
PENDING_REPORTS_LOCK = threading.Lock()
PENDING_REPORT_TTL = 60 * 30  # 30 minutes


def _register_pending_report(payload: dict) -> str:
    notif_id = uuid.uuid4().hex[:12]
    with PENDING_REPORTS_LOCK:
        PENDING_REPORTS[notif_id] = {"ts": time.time(), "payload": payload}
        # opportunistic cleanup of stale entries
        stale = [k for k, v in PENDING_REPORTS.items()
                 if time.time() - v["ts"] > PENDING_REPORT_TTL]
        for k in stale:
            PENDING_REPORTS.pop(k, None)
    return notif_id


def submit_false_positive(notif_id: str) -> bool:
    """Called when the user clicks 'Report false positive' on a toast.

    Posts the original hit payload to our own local report server (same
    endpoint the false_flags.json log already uses), so the click path and
    any future manual reporting path share one code path.
    """
    with PENDING_REPORTS_LOCK:
        entry = PENDING_REPORTS.pop(notif_id, None)
    if not entry:
        print(f"[Apexion] false-positive report clicked for unknown/expired id {notif_id}")
        return False
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{REPORT_SERVER_PORT}/report",
            data=json.dumps(entry["payload"]).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[Apexion] false-positive reported by user (notif_id={notif_id})")
        return True
    except Exception as e:
        print(f"[Apexion] false-positive submit failed: {e}")
        return False

API_HOSTS = {
    "api.anthropic.com":                 ("anthropic", False),
    "api.openai.com":                    ("openai",    False),
    "generativelanguage.googleapis.com": ("google",    False),
}

WEB_UI_HOSTS = {
    "claude.ai":         ("anthropic", True),
    "chatgpt.com":       ("openai",    True),
    "chat.openai.com":   ("openai",    True),
}

ALL_HOSTS = {**API_HOSTS, **WEB_UI_HOSTS}

# Attachments are NOT inside the chat-completion JSON on the web UIs — the image
# is uploaded first (Claude: multipart POST to claude.ai; ChatGPT: raw PUT to
# oaiusercontent / Azure blob; Gemini: resumable raw POST to *.googleapis.com),
# and the completion only references the uploaded file id. So image scanning
# hooks these upload hosts (suffix match). Extend with
# APEXION_EXTRA_UPLOAD_HOSTS=host1,host2 (also matches subdomains).
UPLOAD_HOST_SUFFIXES = {
    "claude.ai": "anthropic", "anthropic.com": "anthropic", "claudeusercontent.com": "anthropic",
    "chatgpt.com": "openai", "openai.com": "openai", "oaiusercontent.com": "openai",
    "openaiusercontent.com": "openai", "blob.core.windows.net": "openai",
    "gemini.google.com": "google", "googleapis.com": "google", "clients6.google.com": "google",
    "perplexity.ai": "perplexity", "copilot.microsoft.com": "microsoft", "x.ai": "xai",
    "grok.com": "xai", "deepseek.com": "deepseek", "mistral.ai": "mistral",
}
for _h in filter(None, (x.strip().lower() for x in os.environ.get("APEXION_EXTRA_UPLOAD_HOSTS", "").split(","))):
    UPLOAD_HOST_SUFFIXES[_h] = _h


def _upload_provider(host: str) -> Optional[str]:
    host = host.lower()
    for suf, prov in UPLOAD_HOST_SUFFIXES.items():
        if host == suf or host.endswith("." + suf):
            return prov
    return None

# Web UI POST paths — prefix match.
# NOTE: If you add a new surface, run with DEBUG_ALL_POSTS=True (below) and
# check the console to find the real path, then add it here.
WEB_COMPLETION_PREFIXES = (
    # ChatGPT web (current 2025)
    "/backend-api/conversation",
    "/backend-anon/conversation",
    "/backend-api/f/",          # function-calling / tool-use variant
    "/backend-api/codex/",
    # Claude web (current 2025)
    "/api/append_message",
    "/api/organizations",       # …/<org_id>/chat_conversations/<id>/completion
    "/api/prompt_completions",
    "/api/auth/",               # sometimes carries message payloads
)

# ── Debug flag ────────────────────────────────────────────────────────────────
# Set True to log EVERY POST/PUT on watched hosts so you can discover real paths
DEBUG_ALL_POSTS = os.environ.get("APEXION_DEBUG_POSTS", "0").lower() in ("1", "true", "yes")
IMAGE_NOTIFY = os.environ.get("APEXION_IMAGE_NOTIFY", "1").lower() not in ("0", "false", "no", "off")

ACTION_RANK = {"warn": 0, "redact": 1, "block": 2}

# Human-readable explanations shown in the 403 body, keyed by hit category.
CATEGORY_EXPLAIN = {
    "prompt_injection": "This message was flagged as a likely prompt-injection / "
                         "jailbreak attempt (instructions trying to override, "
                         "extract, or bypass the assistant's normal behavior) "
                         "and was blocked before reaching the provider.",
    "secrets":          "This message appears to contain an API key, token, or "
                         "credential and was blocked to prevent it from being "
                         "sent to a third-party AI provider.",
    "financial":        "This message appears to contain financial account data "
                         "(card number, IBAN, etc.) and was blocked.",
    "pii":              "This message appears to contain sensitive personal "
                         "identifiers (SSN, CNIC, passport, etc.) and was blocked.",
    "network":          "This message appears to contain internal network/"
                         "infrastructure identifiers and was blocked.",
}
DEFAULT_EXPLAIN = "This message violated a configured data-loss-prevention policy and was blocked."

# If this many distinct prompt_injection signals fire on the same request,
# treat the combination as a jailbreak attempt and escalate every hit in
# that category to "block" — even if each one individually was only "warn".
PROMPT_INJECTION_ESCALATION_THRESHOLD = 2


# ─────────────────────────────────────────────────────────────────────────────
# DLP Engine
# ─────────────────────────────────────────────────────────────────────────────

def _pub(h: dict) -> dict:
    """Public shape of a hit for reports/notifications — includes the PROOF of
    which detection layer produced it."""
    out = {"id": h["id"], "label": h["label"], "category": h.get("category", ""),
           "severity": h["severity"], "action": h["action"]}
    for k in ("escalated", "score", "proof"):
        if h.get(k) is not None and h.get(k) is not False:
            out[k] = h[k]
    return out


def _layer_of(h: dict) -> str:
    pr = h.get("proof") or {}
    return pr.get("layer") or "unknown layer"


class _CombinedRedactEngine:
    """Adapter so apply_redactions()/_rs()/_rb()/_rm() — which only know how
    to call engine.redact(text) — scrub BOTH the Presidio DLP matches AND
    any 'redact'-action custom (taught) detector matches, with no changes
    needed to that provider-shape-specific redaction code."""
    def __init__(self, dlp: "PresidioDLPEngine", custom: "teach_client.CustomDetectorEngine"):
        self._dlp = dlp
        self._custom = custom

    def redact(self, text: str) -> tuple[str, list[dict]]:
        text, dlp_hits = self._dlp.redact(text)
        text, custom_hits = self._custom.redact(text)
        return text, dlp_hits + custom_hits


# ─────────────────────────────────────────────────────────────────────────────
# ML-based prompt-injection / jailbreak guard
#
# Model is swappable via APEXION_PI_MODEL (default: protectai's newer, actively
# maintained deberta-v3 prompt-injection classifier — ungated, no HF token
# needed). Also tested against Meta's Llama-Prompt-Guard-2-86M / -22M, which
# ARE gated: you must accept the license on the model's HF page with the SAME
# account, then set APEXION_HF_TOKEN (or the standard HF_TOKEN) so the
# download is authorized.
#
#   APEXION_PI_MODEL=protectai/deberta-v3-base-prompt-injection-v2   (default)
#   APEXION_PI_MODEL=meta-llama/Llama-Prompt-Guard-2-86M             (gated, needs token)
#   APEXION_PI_MODEL=meta-llama/Llama-Prompt-Guard-2-22M             (gated, smaller/faster)
#
# Different models use different label names for "this is fine" — deepset's
# old model said "LEGIT", protectai's says something else, Prompt Guard says
# "BENIGN" vs "MALICIOUS", Prompt Guard v1 has a THIRD label ("JAILBREAK").
# Hardcoding one string here is how a model swap silently flags 100% of
# traffic as an attack. Instead, _classify_labels() reads the model's own
# config.id2label at load time and sorts each label into safe/unsafe by
# keyword, logs what it decided (check this in the startup log after any
# model swap), and APEXION_PI_SAFE_LABELS lets you override it exactly
# (comma-separated, case-insensitive) if a model's labels don't match any
# keyword we know about.
#
# Loaded once at startup (CPU). If transformers/torch aren't installed, the
# addon falls back to the phrase list in jailbreak_phrases.txt — nothing breaks.
#   pip install transformers torch
#
# Model files are cached locally under models/<model-name>/ (next to this
# script; slashes in the model name become underscores). If that folder
# already contains the model, it loads 100% offline (local_files_only=True,
# no network call at all). Otherwise it downloads once from the Hub and saves
# a copy there for next time. To pre-populate it on a machine with internet
# access, run download_model.py (it reads the same APEXION_PI_MODEL env var).
# ─────────────────────────────────────────────────────────────────────────────

_SAFE_KEYWORDS   = ("safe", "benign", "legit", "legitimate", "normal", "clean")
_UNSAFE_KEYWORDS = ("injection", "inject", "malicious", "jailbreak", "attack", "unsafe", "harmful")


class PromptInjectionGuard:
    MODEL           = os.environ.get("APEXION_PI_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
    HF_TOKEN        = os.environ.get("APEXION_HF_TOKEN") or os.environ.get("HF_TOKEN")
    BLOCK_THRESHOLD = 0.96   # high-confidence injection → 403
    WARN_THRESHOLD  = 0.94   # lower-confidence → pass through + notify

    def __init__(self):
        self.safe_labels: set[str] = set()    # populated by _classify_labels() during _load()
        self.classifier = self._load()

    def _classify_labels(self, model) -> None:
        """Sort this model's own label set into safe/unsafe. Logged so a bad
        guess is visible in the startup log instead of silently misfiring on
        every request."""
        override = os.environ.get("APEXION_PI_SAFE_LABELS")
        id2label = getattr(getattr(model, "config", None), "id2label", None) or {}
        if override:
            self.safe_labels = {s.strip().upper() for s in override.split(",") if s.strip()}
            print(f"[Apexion] prompt-injection safe label(s) from APEXION_PI_SAFE_LABELS: {sorted(self.safe_labels)}")
            return
        safe, unsafe, unknown = [], [], []
        for label in id2label.values():
            lw = str(label).lower()
            if any(k in lw for k in _SAFE_KEYWORDS):
                safe.append(label)
            elif any(k in lw for k in _UNSAFE_KEYWORDS):
                unsafe.append(label)
            else:
                unknown.append(label)
        self.safe_labels = {str(s).upper() for s in safe}
        print(f"[Apexion] prompt-injection guard labels for {self.MODEL}: "
              f"safe={safe} unsafe={unsafe}" + (f" UNRECOGNIZED={unknown}" if unknown else ""))
        if not safe:
            print("[Apexion] WARNING: could not identify a 'safe' label for this model — "
                  "every request may be flagged. Set APEXION_PI_SAFE_LABELS to override, e.g. "
                  "APEXION_PI_SAFE_LABELS=BENIGN")
        if unknown:
            print(f"[Apexion] WARNING: unrecognized label(s) {unknown} — treated as unsafe by default. "
                  "Override with APEXION_PI_SAFE_LABELS if any of these should count as safe.")

    @staticmethod
    def _load_tokenizer(AutoTokenizer, src, **kwargs):
        """AutoTokenizer.from_pretrained with fix_mistral_regex=True when supported.

        Newer transformers versions warn that DeBERTa-family tokenizers were
        built with an incorrect pre-tokenizer regex and offer this flag to
        correct it. Older versions don't accept the kwarg at all, so fall
        back transparently.
        """
        try:
            return AutoTokenizer.from_pretrained(src, fix_mistral_regex=True, **kwargs)
        except TypeError:
            return AutoTokenizer.from_pretrained(src, **kwargs)

    def _load(self):
        model_dir = _model_dir_for(self.MODEL)
        try:
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
                pipeline as hf_pipeline,
            )

            local_ready = model_dir.is_dir() and any(model_dir.iterdir())
            auth = {"token": self.HF_TOKEN} if self.HF_TOKEN else {}

            if local_ready:
                print(f"[Apexion] loading prompt-injection guard from {model_dir} (offline)…")
                tokenizer = self._load_tokenizer(AutoTokenizer, model_dir, local_files_only=True)
                model     = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
            else:
                print(f"[Apexion] {model_dir} not found — downloading {self.MODEL} (one-time, needs internet)…")
                if "meta-llama" in self.MODEL and not self.HF_TOKEN:
                    print("[Apexion] NOTE: this is a gated model — you must accept its license on "
                          "huggingface.co with your account AND set APEXION_HF_TOKEN, or this download will 401.")
                tokenizer = self._load_tokenizer(AutoTokenizer, self.MODEL, **auth)
                model     = AutoModelForSequenceClassification.from_pretrained(self.MODEL, **auth)
                model_dir.mkdir(parents=True, exist_ok=True)
                tokenizer.save_pretrained(model_dir)
                model.save_pretrained(model_dir)
                print(f"[Apexion] cached model to {model_dir} — future runs are fully offline")

            self._classify_labels(model)
            model.eval()
            clf = hf_pipeline(
                task="text-classification",
                model=model,
                tokenizer=tokenizer,
                device=-1,          # CPU
                truncation=True,
                max_length=512,
            )
            print(f"[Apexion] prompt-injection guard ready (ML, {self.MODEL})")
            return clf
        except ImportError as e:
            print(f"[Apexion] {e} — install with: pip install transformers torch")
            print("[Apexion] falling back to phrase-list prompt_injection detection")
            return None
        except Exception as e:
            print(f"[Apexion] prompt-injection model load failed: {e}")
            print("[Apexion] falling back to phrase-list prompt_injection detection")
            return None

    def scan(self, text: str) -> list[dict]:
        if not self.classifier or not text.strip():
            return []
        try:
            raw = self.classifier(text[:2000])[0]   # cap input for latency
        except Exception as e:
            print(f"[Apexion] injection scan error: {e}")
            return []

        if raw["label"].upper() in self.safe_labels:
            return []

        score = raw["score"]
        if score >= self.BLOCK_THRESHOLD:
            action, severity = "block", "critical"
        elif score >= self.WARN_THRESHOLD:
            action, severity = "warn", "high"
        else:
            return []

        return [{
            "id":       "ML_PROMPT_INJECTION",
            "label":    "ML Prompt Injection Detector",
            "category": "prompt_injection",
            "severity": severity,
            "action":   action,
            "score":    round(score, 3),
            "proof": {
                "engine": "ml-classifier",
                "layer": "ML prompt-injection classifier",
                "recognizer": self.MODEL,
                "score": round(score, 3),
                "explanation": (f"Classifier label '{raw['label']}' scored {round(score, 3)} "
                                f"(warn >= {self.WARN_THRESHOLD}, block >= {self.BLOCK_THRESHOLD})"),
                "stages": ["transformer text classification on first 2000 chars"],
            },
        }]


# ─────────────────────────────────────────────────────────────────────────────
# Text extraction — per-provider, matches upstream processor logic
# ─────────────────────────────────────────────────────────────────────────────

def _t(block) -> str:
    if isinstance(block, dict) and block.get("type") == "text":
        return block.get("text", "")
    return ""

def _msgs(messages: list) -> str:
    out = []
    for m in (messages or []):
        if not isinstance(m, dict):
            continue
        c = m.get("content", "")
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, list):
            out.extend(_t(b) for b in c)
    return "\n".join(filter(None, out))


def extract_text(body: dict, provider: str, path: str) -> str:
    parts = []

    if provider == "anthropic":
        if path.startswith("/v1/"):
            # Direct API — /v1/messages
            parts.append(_msgs(body.get("messages")))
            sys = body.get("system", "")
            if isinstance(sys, str):
                parts.append(sys)
            elif isinstance(sys, list):
                parts.extend(_t(b) for b in sys)
        else:
            # Claude web
            if isinstance(body.get("prompt"), str):
                parts.append(body["prompt"])
            msg = body.get("message", {})
            if isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    parts.extend(_t(b) for b in c)
            parts.append(_msgs(body.get("messages")))

    elif provider == "openai":
        is_web_path = any(path.startswith(p) for p in WEB_COMPLETION_PREFIXES)
        if not is_web_path:
            # Direct API
            parts.append(_msgs(body.get("messages")))
            for f in ("system", "instructions"):
                if isinstance(body.get(f), str):
                    parts.append(body[f])
            for item in (body.get("input") or []):
                if isinstance(item, dict):
                    c = item.get("content", "")
                    if isinstance(c, str):
                        parts.append(c)
                    elif isinstance(c, list):
                        parts.extend(_t(b) for b in c)
        else:
            # ChatGPT web — messages[].content is {"content_type":"text","parts":[...]}
            for msg in (body.get("messages") or []):
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content", {})
                if isinstance(content, dict):
                    for part in (content.get("parts") or []):
                        if isinstance(part, str):
                            parts.append(part)
                        elif isinstance(part, dict) and part.get("content_type") == "text":
                            parts.append(part.get("text", ""))
                elif isinstance(content, str):
                    parts.append(content)
            # Codex / Responses API input[]
            for item in (body.get("input") or []):
                if isinstance(item, dict):
                    c = item.get("content", "")
                    if isinstance(c, str):
                        parts.append(c)
            for f in ("instructions", "system"):
                if isinstance(body.get(f), str):
                    parts.append(body[f])

    elif provider == "google":
        for item in (body.get("contents") or []):
            if isinstance(item, dict):
                for part in (item.get("parts") or []):
                    if isinstance(part, dict):
                        parts.append(part.get("text", ""))
        si = body.get("systemInstruction", {})
        if isinstance(si, dict):
            for part in (si.get("parts") or []):
                if isinstance(part, dict):
                    parts.append(part.get("text", ""))

    return "\n".join(filter(None, parts))


def extract_user_text(body: dict, provider: str, path: str) -> str:
    """Extract only the user-authored message text for ML injection scanning.

    Intentionally excludes system prompts and metadata — claude.ai embeds
    internal instructions in the system field that reliably trip the injection
    classifier on every ordinary request.
    """
    parts = []

    if provider == "anthropic":
        if path.startswith("/v1/"):
            # API: only user turns, skip system
            for m in (body.get("messages") or []):
                if isinstance(m, dict) and m.get("role") == "user":
                    c = m.get("content", "")
                    if isinstance(c, str):
                        parts.append(c)
                    elif isinstance(c, list):
                        parts.extend(_t(b) for b in c)
        else:
            # Claude web: prompt field or message.content (user's actual input)
            if isinstance(body.get("prompt"), str):
                parts.append(body["prompt"])
            msg = body.get("message", {})
            if isinstance(msg, dict):
                c = msg.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    parts.extend(_t(b) for b in c)

    elif provider == "openai":
        is_web_path = any(path.startswith(p) for p in WEB_COMPLETION_PREFIXES)

        if not is_web_path:
            for m in (body.get("messages") or []):
                if not isinstance(m, dict):
                    continue

                if m.get("role") != "user":
                    continue

                c = m.get("content", "")
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    parts.extend(_t(b) for b in c)

        else:
            for msg in (body.get("messages") or []):
                if not isinstance(msg, dict):
                    continue

                role = msg.get("role")
                author = msg.get("author", {})

                if role and role != "user":
                    continue

                if isinstance(author, dict):
                    author_role = author.get("role")
                    if author_role and author_role != "user":
                        continue

                content = msg.get("content", {})

                if isinstance(content, dict):
                    for part in (content.get("parts") or []):
                        if isinstance(part, str):
                            parts.append(part)
                        elif (
                            isinstance(part, dict)
                            and part.get("content_type") == "text"
                        ):
                            parts.append(part.get("text", ""))

                elif isinstance(content, str):
                    parts.append(content)

            for item in (body.get("input") or []):
                if not isinstance(item, dict):
                    continue

                if item.get("role") not in (None, "user"):
                    continue

                c = item.get("content", "")

                if isinstance(c, str):
                    parts.append(c)

                elif isinstance(c, list):
                    for block in c:
                        if isinstance(block, dict):
                            if block.get("type") == "input_text":
                                parts.append(block.get("text", ""))
                            elif block.get("type") == "text":
                                parts.append(block.get("text", ""))

    elif provider == "google":
        for item in (body.get("contents") or []):
            if isinstance(item, dict) and item.get("role") in ("user", None, ""):
                for part in (item.get("parts") or []):
                    if isinstance(part, dict):
                        parts.append(part.get("text", ""))

    return "\n".join(filter(None, parts))


# ─────────────────────────────────────────────────────────────────────────────
# Body redaction — per-provider deep copy + replace
# ─────────────────────────────────────────────────────────────────────────────

def _rs(engine, text: str):
    return engine.redact(text)

def _rb(engine, blocks: list):
    hits, out = [], []
    for b in blocks:
        if isinstance(b, dict) and b.get("type") == "text":
            b = dict(b)
            b["text"], h = _rs(engine, b.get("text", ""))
            hits.extend(h)
        out.append(b)
    return out, hits

def _rm(engine, messages: list):
    hits, out = [], []
    for m in (messages or []):
        if isinstance(m, dict):
            m = dict(m)
            c = m.get("content", "")
            if isinstance(c, str):
                m["content"], h = _rs(engine, c)
                hits.extend(h)
            elif isinstance(c, list):
                m["content"], h = _rb(engine, c)
                hits.extend(h)
        out.append(m)
    return out, hits


def apply_redactions(engine, body: dict, provider: str, path: str):
    body  = dict(body)
    hits  = []

    if provider == "anthropic":
        if path.startswith("/v1/"):
            if isinstance(body.get("messages"), list):
                body["messages"], h = _rm(engine, body["messages"]); hits.extend(h)
            sys = body.get("system")
            if isinstance(sys, str):
                body["system"], h = _rs(engine, sys); hits.extend(h)
            elif isinstance(sys, list):
                body["system"], h = _rb(engine, sys); hits.extend(h)
        else:
            if isinstance(body.get("prompt"), str):
                body["prompt"], h = _rs(engine, body["prompt"]); hits.extend(h)
            msg = body.get("message")
            if isinstance(msg, dict):
                msg = dict(msg)
                c = msg.get("content", "")
                if isinstance(c, str):
                    msg["content"], h = _rs(engine, c); hits.extend(h)
                elif isinstance(c, list):
                    msg["content"], h = _rb(engine, c); hits.extend(h)
                body["message"] = msg
            if isinstance(body.get("messages"), list):
                body["messages"], h = _rm(engine, body["messages"]); hits.extend(h)

    elif provider == "openai":
        is_web_path = any(path.startswith(p) for p in WEB_COMPLETION_PREFIXES)
        if not is_web_path:
            if isinstance(body.get("messages"), list):
                body["messages"], h = _rm(engine, body["messages"]); hits.extend(h)
            for f in ("system", "instructions"):
                if isinstance(body.get(f), str):
                    body[f], h = _rs(engine, body[f]); hits.extend(h)
            inp = body.get("input")
            if isinstance(inp, list):
                new_inp = []
                for item in inp:
                    if isinstance(item, dict):
                        item = dict(item)
                        c = item.get("content", "")
                        if isinstance(c, str):
                            item["content"], h = _rs(engine, c); hits.extend(h)
                        elif isinstance(c, list):
                            item["content"], h = _rb(engine, c); hits.extend(h)
                    new_inp.append(item)
                body["input"] = new_inp
        else:
            msgs = body.get("messages")
            if isinstance(msgs, list):
                new_msgs = []
                for msg in msgs:
                    if isinstance(msg, dict):
                        msg = dict(msg)
                        content = msg.get("content", {})
                        if isinstance(content, dict):
                            content = dict(content)
                            new_parts = []
                            for part in (content.get("parts") or []):
                                if isinstance(part, str):
                                    part, h = _rs(engine, part); hits.extend(h)
                                new_parts.append(part)
                            content["parts"] = new_parts
                            msg["content"] = content
                        elif isinstance(content, str):
                            msg["content"], h = _rs(engine, content); hits.extend(h)
                    new_msgs.append(msg)
                body["messages"] = new_msgs
            inp = body.get("input")
            if isinstance(inp, list):
                new_inp = []
                for item in inp:
                    if isinstance(item, dict):
                        item = dict(item)
                        c = item.get("content", "")
                        if isinstance(c, str):
                            item["content"], h = _rs(engine, c); hits.extend(h)
                    new_inp.append(item)
                body["input"] = new_inp
            for f in ("instructions", "system"):
                if isinstance(body.get(f), str):
                    body[f], h = _rs(engine, body[f]); hits.extend(h)

    elif provider == "google":
        contents = body.get("contents")
        if isinstance(contents, list):
            new_c = []
            for item in contents:
                if isinstance(item, dict):
                    item = dict(item)
                    new_parts = []
                    for part in (item.get("parts") or []):
                        if isinstance(part, dict) and "text" in part:
                            part = dict(part)
                            part["text"], h = _rs(engine, part["text"]); hits.extend(h)
                        new_parts.append(part)
                    item["parts"] = new_parts
                new_c.append(item)
            body["contents"] = new_c
        si = body.get("systemInstruction")
        if isinstance(si, dict):
            si = dict(si)
            new_parts = []
            for part in (si.get("parts") or []):
                if isinstance(part, dict) and "text" in part:
                    part = dict(part)
                    part["text"], h = _rs(engine, part["text"]); hits.extend(h)
                new_parts.append(part)
            si["parts"] = new_parts
            body["systemInstruction"] = si

    return body, hits


# ─────────────────────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_completion_path(path: str, provider: str) -> bool:
    for prefix in WEB_COMPLETION_PREFIXES:
        if path.startswith(prefix):
            return True
    # Claude web org-scoped: /api/organizations/<uuid>/…/completion
    if provider == "anthropic" and "/completion" in path:
        return True
    return False


def extract_model(body: dict, provider: str) -> str:
    if "model" in body:
        return str(body["model"])
    return "claude-web" if provider == "anthropic" else "gpt-4o"



# ─────────────────────────────────────────────────────────────────────────────
# Native push notifications — platform detected once at startup
# ─────────────────────────────────────────────────────────────────────────────

_OS = platform.system()   # "Darwin" | "Windows" | "Linux"


def _as_str(s: str) -> str:
    """Escape a string for use inside an AppleScript double-quoted string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _ensure_icon() -> "Optional[Path]":
    """Generate a simple Apexion shield+lock icon once, cached on disk.

    terminal-notifier's default icon is the Terminal app icon — this swaps it
    for a recognizable Apexion mark. Drawn with plain shapes (no font
    dependency) via Pillow (pip install pillow); if unavailable, notifications
    just fall back to the default icon.
    """
    if ICON_FILE.exists():
        return ICON_FILE
    try:
        from PIL import Image, ImageDraw
        size = 256
        img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d    = ImageDraw.Draw(img)

        # Shield silhouette
        shield = [(28, 30), (228, 30), (228, 130), (128, 240), (28, 130)]
        d.polygon(shield, fill=(196, 30, 58, 255))

        # Padlock body
        d.rounded_rectangle([88, 128, 168, 188], radius=14, fill="white")
        # Padlock shackle (arc)
        d.arc([100, 80, 156, 160], start=180, end=360, fill="white", width=14)

        img.save(ICON_FILE)
        return ICON_FILE
    except Exception as e:
        print(f"[Apexion] icon generation skipped ({e}); using default icon")
        return None


REPORT_ACTION_LABEL = "Report false positive"


def _notify_macos(title: str, body: str, notif_id: "Optional[str]" = None):
    body_flat = body.replace("\n", " | ")

    # ── Tier 1: terminal-notifier (most reliable, bypasses permission dialog) ──
    # Install once: brew install terminal-notifier
    # When notif_id is set we add a single action button. terminal-notifier
    # blocks (with -wait) and prints which action was clicked to stdout, so we
    # run it in this same background thread and react to the result.
    if shutil.which("terminal-notifier"):
        cmd = ["terminal-notifier",
               "-title",   "Apexion DLP",
               "-subtitle", title,
               "-message",  body_flat,
               "-sound",    "Basso",
               "-ignoreDnD"]
        icon = _ensure_icon()
        if icon:
            # -appIcon replaces the small icon; -contentImage adds the larger
            # thumbnail shown alongside the message.
            cmd += ["-appIcon", str(icon), "-contentImage", str(icon)]

        if notif_id:
            cmd += ["-actions", REPORT_ACTION_LABEL, "-wait"]
            r = subprocess.run(cmd, capture_output=True, timeout=120)
            if r.returncode == 0:
                clicked = r.stdout.decode().strip()
                if REPORT_ACTION_LABEL in clicked:
                    submit_false_positive(notif_id)
                return
            print(f"[Apexion] terminal-notifier error: {r.stderr.decode().strip()}")
        else:
            r = subprocess.run(cmd, capture_output=True, timeout=8)
            if r.returncode == 0:
                return
            print(f"[Apexion] terminal-notifier error: {r.stderr.decode().strip()}")

    # ── Tier 2: osascript display notification ─────────────────────────────────
    # Requires: System Preferences → Notifications → Script Editor → Allow
    # Note: AppleScript's `display notification` always shows the sending
    # app's icon (Script Editor) — there's no per-notification icon override
    # at this tier, and no action-button support either. Install
    # terminal-notifier for the custom Apexion icon and the report button.
    lines    = body.split("\n")
    body_as  = '" & return & "'.join(_as_str(l) for l in lines)
    title_as = _as_str(title)
    r2 = subprocess.run(
        ["osascript", "-e",
         f'display notification "{body_as}" with title "{title_as}" sound name "Basso"'],
        capture_output=True, timeout=5
    )
    if r2.returncode == 0:
        if notif_id:
            print("[Apexion] no 'Report false positive' button available at this "
                  "notification tier — install terminal-notifier for that, or run "
                  "submit_false_positive() manually.")
        return
    print(f"[Apexion] osascript notification failed: {r2.stderr.decode().strip()}")

    # ── Tier 3: osascript alert dialog (always works, no permissions needed) ───
    # This tier IS interactive, so we can offer a real button here.
    if notif_id:
        msg_as = _as_str(f"{title}\n{body_flat}")
        r3 = subprocess.run(
            ["osascript", "-e",
             f'tell app "System Events" to display alert "Apexion DLP" message "{msg_as}" '
             f'buttons {{"Dismiss", "{REPORT_ACTION_LABEL}"}} default button "Dismiss"'],
            capture_output=True, timeout=120
        )
        if r3.returncode == 0 and REPORT_ACTION_LABEL in r3.stdout.decode():
            submit_false_positive(notif_id)
        return

    msg_as = _as_str(f"{title}\n{body_flat}")
    subprocess.run(
        ["osascript", "-e",
         f'tell app "System Events" to display alert "Apexion DLP" message "{msg_as}"'],
        capture_output=True, timeout=5
    )


# Windows toast buttons fire via "protocol activation" — clicking the button
# launches a URI. We register a custom apexion-report:// protocol once at
# startup (HKCU, no admin needed) whose handler relays the clicked id to our
# own report endpoint, then the toast can include a real action button.
_WIN_PROTOCOL_REGISTERED = False


def _win_register_protocol():
    """One-time HKCU registration of the apexion-report:// URI protocol.

    The handler runs python (no console flash, via -c) which POSTs straight
    to our local report server using the id passed in the URI
    (apexion-report://<notif_id>) and exits. Safe to call every startup —
    overwriting the same keys is a no-op if nothing changed.
    """
    global _WIN_PROTOCOL_REGISTERED
    if _WIN_PROTOCOL_REGISTERED:
        return
    try:
        handler_py = (
            "import sys,urllib.request,json;"
            "u=sys.argv[1].split('://',1)[-1].strip('/');"
            "req=urllib.request.Request("
            f"'http://127.0.0.1:{REPORT_SERVER_PORT}/report_click',"
            "data=json.dumps({'notif_id':u}).encode(),"
            "headers={'Content-Type':'application/json'},method='POST');"
            "urllib.request.urlopen(req,timeout=5)"
        )
        handler_cmd = f'"{sys.executable}" -c "{handler_py}" "%1"'
        ps = (
            "$base = 'Registry::HKCU\\Software\\Classes\\apexion-report'; "
            "New-Item -Path $base -Force | Out-Null; "
            "Set-ItemProperty -Path $base -Name '(Default)' -Value 'URL:Apexion Report Protocol'; "
            "Set-ItemProperty -Path $base -Name 'URL Protocol' -Value ''; "
            "New-Item -Path \"$base\\shell\\open\\command\" -Force | Out-Null; "
            f"Set-ItemProperty -Path \"$base\\shell\\open\\command\" -Name '(Default)' -Value '{handler_cmd}'"
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            _WIN_PROTOCOL_REGISTERED = True
        else:
            print(f"[Apexion] could not register apexion-report:// protocol: "
                  f"{r.stderr.decode().strip()[:160]}")
    except Exception as e:
        print(f"[Apexion] win protocol registration error: {e}")


def _notify_windows(title: str, body: str, notif_id: "Optional[str]" = None):
    body_flat = body.replace("\n", " | ")

    if notif_id:
        _win_register_protocol()
        # Toast with one button, activated via our custom protocol.
        ps = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null; "
            "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; "
            f"$xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\">"
            f"<text>{title}</text><text>{body_flat}</text></binding></visual>"
            f"<actions><action content=\"{REPORT_ACTION_LABEL}\" "
            f"arguments=\"apexion-report://{notif_id}\" activationType=\"protocol\"/>"
            f"<action content=\"Dismiss\" arguments=\"dismiss\" activationType=\"system\"/>"
            f"</actions></toast>'); "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
            "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Apexion DLP'); "
            "$notifier.Show($toast)"
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return
        print(f"[Apexion] win actionable toast error: {r.stderr.decode().strip()[:160]} "
              f"— falling back to plain toast")

    # Try PowerShell + BurntToast
    bt = (
        "Import-Module BurntToast -ErrorAction Stop; "
        f"New-BurntToastNotification -Text '{title}','{body_flat}'"
    )
    r = subprocess.run(
        ["powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", bt],
        capture_output=True, timeout=10
    )
    if r.returncode == 0:
        return

    # Fallback: Windows 10/11 toast via PowerShell without BurntToast
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] | Out-Null; "
        f"$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        f"$xml.GetElementsByTagName('text')[0].AppendChild($xml.CreateTextNode('{title}')) | Out-Null; "
        f"$xml.GetElementsByTagName('text')[1].AppendChild($xml.CreateTextNode('{body_flat}')) | Out-Null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
        "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Apexion DLP'); "
        "$notifier.Show($toast)"
    )
    r2 = subprocess.run(
        ["powershell", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps],
        capture_output=True, timeout=10
    )
    if r2.returncode != 0:
        print(f"[Apexion] win notify error: {r2.stderr.decode().strip()[:120]}")


def _linux_watch_action(notif_id: str, dbus_id: str, timeout: int = 30):
    """Watch for the ActionInvoked D-Bus signal for our notification and
    submit the false-positive report if our action key was clicked."""
    try:
        proc = subprocess.Popen(
            ["gdbus", "monitor", "--session", "--dest", "org.freedesktop.Notifications"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
    except Exception as e:
        print(f"[Apexion] gdbus monitor unavailable: {e}")
        return

    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                continue
            if "ActionInvoked" in line and dbus_id in line and "apexion-report" in line:
                submit_false_positive(notif_id)
                break
    finally:
        proc.terminate()


def _notify_linux(title: str, body: str, notif_id: "Optional[str]" = None):
    body_flat = body.replace("\n", " | ")

    # Actionable path: talk to libnotify directly over D-Bus so we can attach
    # a real action button (notify-send's CLI has no action support).
    if notif_id and shutil.which("gdbus"):
        try:
            call = subprocess.run(
                ["gdbus", "call", "--session",
                 "--dest", "org.freedesktop.Notifications",
                 "--object-path", "/org/freedesktop/Notifications",
                 "--method", "org.freedesktop.Notifications.Notify",
                 "Apexion DLP", "0", "",
                 title, body_flat,
                 f"['apexion-report', '{REPORT_ACTION_LABEL}']",
                 "{'urgency': <byte 2>}", "10000"],
                capture_output=True, timeout=8, text=True,
            )
            if call.returncode == 0:
                # Output looks like "(uint32 42,)" — the D-Bus notification id.
                dbus_id = call.stdout.strip().strip("(),").replace("uint32 ", "")
                threading.Thread(
                    target=_linux_watch_action, args=(notif_id, dbus_id), daemon=True
                ).start()
                return
            print(f"[Apexion] gdbus notify error: {call.stderr.strip()[:160]}")
        except Exception as e:
            print(f"[Apexion] gdbus notify failed: {e}")
        if notif_id:
            print("[Apexion] falling back to a plain (button-less) notification")

    for cmd in (
        ["notify-send", "-a", "Apexion DLP", "-u", "critical", "-t", "10000", title, body_flat],
        ["zenity", "--notification", f"--text={title}: {body_flat}"],
        ["xmessage", "-timeout", "10", f"{title}\n{body_flat}"],
    ):
        if shutil.which(cmd[0]):
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    print(f"[Apexion] no notification tool found (install libnotify-bin)")


def notify(title: str, body: str, report_payload: "Optional[dict]" = None):
    """Fire a native OS push notification in a background thread.

    If report_payload is given, the notification includes a
    'Report false positive' action button. Clicking it POSTs report_payload
    to the local /report endpoint (same place false_flags.json entries come
    from), so a human marking something as wrongly flagged is captured the
    same way as any other false-flag report.
    """
    notif_id = _register_pending_report(report_payload) if report_payload else None

    def _run():
        try:
            if _OS == "Darwin":
                _notify_macos(title, body, notif_id)
            elif _OS == "Windows":
                _notify_windows(title, body, notif_id)
            else:
                _notify_linux(title, body, notif_id)
        except Exception as e:
            print(f"[Apexion] notify error ({_OS}): {e}")
    threading.Thread(target=_run, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# False-flag report server  127.0.0.1:8081
# Page JS POSTs here → appended to false_flags.json
# ─────────────────────────────────────────────────────────────────────────────

class _ReportHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        if self.path == "/report_click":
            # Hit by the Windows apexion-report:// protocol handler when the
            # user clicks "Report false positive" on a toast. Just resolves
            # the short notif_id back to the full payload and forwards it.
            try:
                length = int(self.headers.get("Content-Length", 0))
                body   = json.loads(self.rfile.read(length))
                notif_id = body.get("notif_id", "")
            except Exception:
                self.send_response(400); self.end_headers(); return
            ok = submit_false_positive(notif_id)
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": ok}).encode())
            return

        if self.path != "/report":
            self.send_response(404); self.end_headers(); return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            self.send_response(400); self.end_headers(); return
        try:
            log = json.loads(FALSE_FLAGS_FILE.read_text()) if FALSE_FLAGS_FILE.exists() else []
            log.append(body)
            FALSE_FLAGS_FILE.write_text(json.dumps(log, indent=2))
            print(f"[Apexion] false-flag logged ({len(log)} total): "
                  + ", ".join(h.get("id", "?") for h in body.get("hits", [])))
            resp = json.dumps({"ok": True, "total": len(log)}).encode()
        except Exception as e:
            print(f"[Apexion] false-flag write error: {e}")
            resp = json.dumps({"ok": False, "error": str(e)}).encode()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")


def start_report_server():
    srv = HTTPServer(("127.0.0.1", REPORT_SERVER_PORT), _ReportHandler)
    t   = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[Apexion] report server on 127.0.0.1:{REPORT_SERVER_PORT}/report")



# ─────────────────────────────────────────────────────────────────────────────
# Main Addon
# ─────────────────────────────────────────────────────────────────────────────

class ApexionAddon:
    def __init__(self):
        self.dlp   = PresidioDLPEngine(DLP_POLICY_FILE)
        manager_client.report_catalog(self.dlp.catalog())   # auto-discovered interceptable entities
        self.guard = PromptInjectionGuard()
        self._pending: dict[str, dict] = {}

        # Prompt-injection (Vigil) settings from manager server — defaults to
        # all-enabled if no server is configured. Refreshed periodically by
        # _pi_settings_poll_loop.
        self.pi_settings = manager_client.fetch_pi_settings()
        self._start_pi_settings_poller()

        # Taught (custom) detectors from the Teach Astral admin page. Loads
        # whatever is cached on disk immediately (works offline / before the
        # first poll), then refreshes in the background — no process restart
        # needed, unlike the .policy_cache.json reload.
        self.custom = teach_client.CustomDetectorEngine()
        self._start_custom_poller()

        # Image (OCR + Presidio) scanning — inline base64 images in JSON bodies
        # and multipart image uploads. Off with APEXION_IMAGE_SCAN=0.
        self.images = image_scanner.ImageScanner(self.dlp, self.custom) if image_scanner.ENABLED else None
        # request() is async: scans run on worker threads so a slow OCR/ML pass
        # holds ONLY its own request (upload waits for the verdict) instead of
        # freezing the whole proxy event loop.
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="apexion")

    def _start_custom_poller(self):
        if not manager_client.ENABLED:
            return

        def _loop():
            while True:
                manifest = manager_client.fetch_custom_manifest()
                if manifest:
                    try:
                        self.custom.apply_manifest(manifest)
                    except Exception as e:
                        print(f"[Apexion] custom detector manifest apply failed: {e}")
                time.sleep(manager_client.POLL_INTERVAL_SECS)

        threading.Thread(target=_loop, daemon=True).start()

    def _start_pi_settings_poller(self):
        if not manager_client.ENABLED:
            return

        def _loop():
            while True:
                time.sleep(manager_client.POLL_INTERVAL_SECS)
                self.pi_settings = manager_client.fetch_pi_settings()

        threading.Thread(target=_loop, daemon=True).start()

    async def request(self, flow: http.HTTPFlow):
        # mitmproxy awaits this hook BEFORE forwarding the request, so nothing
        # (incl. image uploads) leaves the machine until the scan verdict is in.
        await asyncio.get_running_loop().run_in_executor(self._pool, self._request_sync, flow)

    def _img_notify(self, title: str, body: str):
        if IMAGE_NOTIFY:
            notify(title, body)

    def _request_sync(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        path   = flow.request.path
        method = flow.request.method

        # Attachment uploads (multipart / raw image bytes) on any AI upload host.
        if self.images and method in ("POST", "PUT", "PATCH"):
            up_provider = (ALL_HOSTS.get(host) or (None,))[0] or _upload_provider(host)
            if up_provider:
                ct0 = flow.request.headers.get("content-type", "").lower()
                if "json" not in ct0 and "text/" not in ct0:
                    if self._handle_upload(flow, up_provider, path):
                        return

        if host not in ALL_HOSTS:
            return

        provider, is_web = ALL_HOSTS[host]

        # ── Debug: log every non-GET so we can see real conversation paths ──
        if DEBUG_ALL_POSTS and method in ("POST", "PUT", "PATCH"):
            ct = flow.request.headers.get("content-type", "")
            print(f"[DEBUG] {method} {host}{path}  ct={ct}")

        # For web UIs only process completion endpoints
        if is_web and not is_completion_path(path, provider):
            return

        # For API hosts only process POST (completions are always POST)
        if not is_web and method != "POST":
            return

        # Must have a JSON body
        ct = flow.request.headers.get("content-type", "")
        if "application/json" not in ct and not is_web:
            return

        self._pending[flow.id] = {
            "ts": time.time(), "provider": provider,
            "is_web": is_web, "path": path,
        }

        try:
            raw  = flow.request.get_text() or ""
            body = json.loads(raw)
        except Exception:
            print(f"[Apexion] could not parse body: {host}{path}")
            return

        text = extract_text(body, provider, path)
        batch = image_scanner.ImageBatch()
        if self.images:
            n_imgs = len(image_scanner.find_images(body)[0])
            if n_imgs:
                self._img_notify("Apexion — scanning attached image" + ("s" if n_imgs > 1 else ""),
                                 "Holding the request until the image is checked for sensitive data…")
            batch = self.images.scan_body(body)
            flow.metadata["apexion_image"] = {"images": batch.count, "ms": batch.ms, "ocr_chars": sum(map(len, batch.ocr)),
                                              "hits": [(h["id"], h["action"]) for h in batch.hits]}
        if not text.strip() and not batch.active:
            print(f"[Apexion] empty extracted text: {host}{path} | body keys={list(body.keys())}")
            return
        report_text = text + batch.report_suffix()   # what dashboards/notifications show

        # Presidio DLP scan on full extracted text (+ image hits from OCR + Presidio)
        all_hits = self.dlp.scan(text) if text.strip() else []
        all_hits += batch.hits

        # Taught (custom) detectors — same hit shape, so they fold straight
        # into escalate()/worst_action() below. Uncertain candidates are
        # NEVER enforced here; they're reported to the server's Yes/No queue.
        custom_hits, custom_uncertain = self.custom.scan_hits(text) if text.strip() else ([], [])
        if custom_hits:
            all_hits += custom_hits
            print(f"[Apexion] custom detectors: {[h['id'] for h in custom_hits]}")
        for u in custom_uncertain:
            manager_client.report_custom_question(
                u["detector_id"], u["context"], u["value"], u["confidence"]
            )

        # Weak NER-only hits (warn: names/locations) don't explain a PI score,
        # so only enforceable non-PI entities justify skipping the ML scan.
        pii_explains = any(h["action"] != "warn" and h["category"] != "prompt_injection"
                           for h in all_hits)
        if self.guard.classifier:
            # Skip ML scan if Presidio DLP already explains the content (e.g. email,
            # phone, SSN). The injection model scores PII-bearing messages very high
            # as false positives — if DLP already flagged it, that's the explanation.
            if pii_explains:
                print(f"[Apexion] ML scan skipped — Presidio entities explain content "
                      f"({[h['id'] for h in all_hits]})")
            else:
                user_text = (extract_user_text(body, provider, path) + "\n" + batch.ocr_text).strip()
                ml_hits = self.guard.scan(user_text) if user_text.strip() else []

                # Apply server-controlled Vigil settings: block_enabled /
                # warn_enabled gate whether each action level is applied at
                # all (a disabled level is dropped, not downgraded).
                pis = self.pi_settings
                filtered_ml_hits = []
                for h in ml_hits:
                    if h["action"] == "block" and not pis.get("block_enabled", True):
                        continue
                    if h["action"] == "warn" and not pis.get("warn_enabled", True):
                        continue
                    filtered_ml_hits.append(h)

                # Report every ML hit (warn + block) to the Vigil dashboard,
                # regardless of whether it was filtered above — the server
                # should see attempts even if a client disabled enforcement.
                for h in ml_hits:
                    manager_client.report_pi(
                        provider=provider, path=path,
                        action=h["action"], score=h.get("score"),
                        hits=[_pub(h)],
                        prompt=user_text,
                    )

                all_hits += filtered_ml_hits
        else:
            # Fallback: report phrase-list PI hits to Vigil dashboard
            phrase_pi_hits = [h for h in all_hits if h["category"] == "prompt_injection"]
            for h in phrase_pi_hits:
                manager_client.report_pi(
                    provider=provider, path=path,
                    action=h["action"], score=None,
                    hits=[_pub(h)],
                    prompt=report_text,
                )

        all_hits = self.dlp.escalate(all_hits)
        worst    = self.dlp.worst_action(all_hits)

        if worst == "none":
            return

        print(f"[Apexion] {provider} {path} | hits={len(all_hits)} worst={worst}")
        for h in all_hits:
            tag   = " [ESCALATED-JAILBREAK]" if h.get("escalated") else ""
            score = f" score={h['score']}" if "score" in h else ""
            print(f"  [{h['severity'].upper()}] {h['label']} → {h['action']}{score}{tag}"
                  f"  ← layer: {_layer_of(h)}"
                  + (f" / {h['proof']['recognizer']}" if (h.get('proof') or {}).get('recognizer') else ""))

        if worst == "block":
            block_hits = [h for h in all_hits if h["action"] == "block"]

            # One explanation per distinct category among the blocking hits
            categories = []
            for h in block_hits:
                if h["category"] not in categories:
                    categories.append(h["category"])
            reasons = [CATEGORY_EXPLAIN.get(c, DEFAULT_EXPLAIN) for c in categories]

            detail = []
            for h in block_hits:
                d = _pub(h)
                if "score" in h:
                    d["confidence"] = h["score"]
                if h.get("escalated"):
                    d["note"] = ("Escalated: multiple jailbreak signals detected "
                                  "together in this message")
                detail.append(d)

            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error":  "Apexion DLP: request blocked",
                    "reason": " ".join(reasons),
                    "hits":   detail,
                }),
                {"Content-Type": "application/json",
                 "X-Apexion-Action": "block"},
            )
            dlp_block_hits = [h for h in all_hits if h["category"] != "prompt_injection"]
            if dlp_block_hits:
                manager_client.report_dlp(
                    provider=provider, path=path, worst_action="block",
                    hits=[_pub(h)
                          for h in dlp_block_hits],
                    prompt=report_text,
                )

            # Push notification for blocked hits. ML prompt-injection blocks
            # are gated by the server-controlled push_enabled setting; DLP
            # category blocks always notify.
            is_pi_only_block = all(h["id"] == "ML_PROMPT_INJECTION" for h in block_hits)
            if not (is_pi_only_block and not self.pi_settings.get("push_enabled", True)):
                title = (f"Apexion DLP — {len(block_hits)} pattern"
                         f"{'s' if len(block_hits) > 1 else ''} blocked")
                notif_body = "\n".join(
                    f"[{h['severity'].upper()}] {h['label']} — {_layer_of(h)}" for h in block_hits
                )
                report_payload = {
                    "client_id": getattr(manager_client, "CLIENT_ID", ""),
                    "provider":  provider,
                    "path":      path,
                    "action":    "block",
                    "hits": [_pub(h)
                             for h in block_hits],
                    "prompt": report_text,
                }
                notify(title, notif_body, report_payload=report_payload)
            print(f"[Apexion] blocked: "
                  + "; ".join(f"{h['id']}({h['severity']})" for h in block_hits))

            del self._pending[flow.id]
            return

        if worst == "redact":
            body, redact_hits = apply_redactions(_CombinedRedactEngine(self.dlp, self.custom), body, provider, path)
            body, n_img = batch.apply(body)          # paint boxes over PII pixels
            img_redact_hits = [h for h in batch.hits if h["action"] == "redact"] if n_img else []
            if redact_hits or n_img:
                flow.request.set_text(json.dumps(body))
                print(f"[Apexion] body redacted — {[h['id'] for h in redact_hits + img_redact_hits]}"
                      + (f" ({n_img} image(s) pixel-redacted)" if n_img else ""))

            # Report what was ACTUALLY redacted (redact_hits, from the
            # per-field pass that ran against the real request body) — NOT
            # all_hits, which came from an earlier whole-text scan that ran
            # BEFORE redaction and can diverge from it (missing context words
            # once a value sits alone in its own field, a different action
            # per field, or a stale proof object). Any PI-category or
            # warn-only entity that all_hits saw but the per-field redact
            # pass didn't touch (nothing to redact there) is still reported,
            # since it's still true and still didn't change the request body.
            redacted_ids = {h["id"] for h in redact_hits}
            carried_hits = [h for h in all_hits
                           if h["id"] not in redacted_ids
                           and h["action"] in ("warn", "block")]
            report_hits = redact_hits + img_redact_hits + carried_hits

            # carry any warn hits forward to response hook
            self._pending[flow.id]["warn_hits"] = [h for h in report_hits if h["action"] == "warn"]
            self._pending[flow.id]["prompt"] = report_text
            dlp_hits = [h for h in report_hits if h["category"] != "prompt_injection"]
            if dlp_hits:
                manager_client.report_dlp(
                    provider=provider, path=path, worst_action="redact",
                    hits=[_pub(h) for h in dlp_hits],
                    prompt=report_text,
                )
            if not redact_hits and not n_img and dlp_hits:
                print(f"[Apexion] WARNING: worst_action=redact but nothing was "
                      f"actually redacted in the body — reporting pre-redaction "
                      f"hits only: {[h['id'] for h in dlp_hits]}")
            return

        # worst == "warn"
        self._pending[flow.id]["warn_hits"] = [h for h in all_hits if h["action"] == "warn"]
        self._pending[flow.id]["prompt"] = report_text
        dlp_warn_hits = [h for h in all_hits if h["category"] != "prompt_injection"]
        if dlp_warn_hits:
            manager_client.report_dlp(
                provider=provider, path=path, worst_action="warn",
                hits=[_pub(h) for h in dlp_warn_hits],
                prompt=report_text,
            )

    def _handle_upload(self, flow: http.HTTPFlow, provider: str, path: str) -> bool:
        """Scan image bytes in an upload (multipart part or raw body). Returns True
        if the request carried an image and was handled (blocked/redacted/reported)."""
        req = flow.request
        ct = req.headers.get("content-type", "").lower()
        content = req.content or b""
        mode, blobs = "raw", []
        try:
            if "multipart/form-data" in ct:
                mode = "multipart"
                blobs = [v for v in image_scanner.multipart_parts(req.headers.get("content-type", ""), content)
                         if image_scanner.sniff_image(v)]
            elif len(content) <= image_scanner.MAX_BYTES * 2 and image_scanner.sniff_image(content):
                blobs = [bytes(content)]
        except Exception as e:
            print(f"[Apexion] upload parse error {req.pretty_host}{path}: {e}")
            return False
        if not blobs:
            if DEBUG_ALL_POSTS:
                print(f"[Apexion] upload (no image) {req.method} {req.pretty_host}{path} ct={ct[:40]} size={len(content)}")
            return False

        print(f"[Apexion] IMAGE UPLOAD {req.method} {req.pretty_host}{path} ({mode}, {len(blobs)} image(s), {len(content)} bytes)"
              " — holding until scan completes")
        self._img_notify("Apexion — scanning attached image", "Upload is held until the image is checked for sensitive data…")
        batch = self.images.scan_raw(blobs)
        hits = self.dlp.escalate(list(batch.hits))
        worst = self.dlp.worst_action(hits)
        flow.metadata["apexion_image"] = {"images": batch.count, "ms": batch.ms, "ocr_chars": sum(map(len, batch.ocr)),
                                          "worst": worst, "hits": [(h["id"], h["action"]) for h in hits]}
        if worst == "none":
            self._img_notify("Apexion — image cleared", "No sensitive data found; upload released.")
            print("[Apexion]   image scan: clean" + (f" ({len(batch.ocr)} with text)" if batch.ocr else " (no text found)"))
            return True
        print(f"[Apexion]   image hits={[(h['id'], h['action']) for h in hits]} worst={worst}")
        rtext = "[image upload]" + batch.report_suffix()
        if worst == "block":
            blk = [h for h in hits if h["action"] == "block"]
            reason = " ".join(dict.fromkeys(
                CATEGORY_EXPLAIN.get(h["category"], DEFAULT_EXPLAIN) for h in blk if h["category"] != "image_scan")) \
                or "This image could not be verified against the data-loss-prevention policy and was blocked."
            flow.response = http.Response.make(403, json.dumps({
                "error": "Apexion DLP: image upload blocked", "reason": reason,
                "hits": [_pub(h) for h in blk]}),
                {"Content-Type": "application/json", "X-Apexion-Action": "block"})
            manager_client.report_dlp(provider=provider, path=path, worst_action="block",
                                      hits=[_pub(h) for h in blk], prompt=rtext)
            notify("Apexion DLP — image upload blocked",
                   "\n".join(f"[{h['severity'].upper()}] {h['label']}" for h in blk))
            return True
        if worst == "redact":
            n = 0
            self._img_notify("Apexion — image redacted", "Sensitive data was blacked out before upload.")
            for raw in blobs:
                sc = batch.scans.get(hashlib.sha256(raw).hexdigest())
                if not (sc and sc.redacted):
                    continue
                new, mime = sc.redacted
                if mode == "raw":
                    req.content = new
                    if ct.startswith("image/") and mime != ct.split(";")[0]:
                        req.headers["content-type"] = mime
                    if "x-ms-blob-content-type" in req.headers:
                        req.headers["x-ms-blob-content-type"] = mime
                    n += 1
                elif raw in req.content:
                    req.content = req.content.replace(raw, new, 1); n += 1
            print(f"[Apexion]   {n} uploaded image(s) pixel-redacted")
        manager_client.report_dlp(provider=provider, path=path, worst_action=worst,
                                  hits=[_pub(h) for h in hits], prompt=rtext)
        return True

    def responseheaders(self, flow: http.HTTPFlow):
        """Let SSE/chunked completion responses stream straight through.

        Without this, mitmproxy buffers the full response body before the
        `response` hook fires — so the client gets nothing until the model
        has finished generating, instead of token-by-token streaming.
        Setting `stream = True` here makes mitmproxy relay each chunk to the
        client immediately. We don't need the buffered body anywhere
        downstream (the `response` hook below only uses metadata recorded
        during `request`), so this is safe for every flow we track.
        """
        if flow.id not in self._pending or not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "text/event-stream" in ct or "ndjson" in ct or "stream" in ct:
            flow.response.stream = True
        elif flow.response.headers.get("transfer-encoding", "").lower() == "chunked":
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow):
        if capture.ENABLED:
            try:
                h = flow.request.pretty_host
                capture.record(flow, bool(ALL_HOSTS.get(h) or _upload_provider(h)), flow.metadata.get("apexion_image"))
            except Exception as e:
                print(f"[CAPTURE] error: {type(e).__name__}: {e}")
        meta = self._pending.pop(flow.id, None)
        if not meta or not flow.response:
            return
        warn_hits = meta.get("warn_hits")
        if not warn_hits:
            return
        hits_payload = [
            _pub(h)
            for h in warn_hits
        ]
        title = f"Apexion DLP — {len(hits_payload)} pattern{'s' if len(hits_payload)>1 else ''} flagged"
        body  = "\n".join(f"[{h['severity'].upper()}] {h['label']} — {_layer_of(h)}" for h in hits_payload)

        # Prompt-injection warn/block notifications can be toggled off by the
        # manager server (push_enabled). DLP notifications are always shown.
        is_pi_only = all(h["id"] == "ML_PROMPT_INJECTION" for h in warn_hits)
        if is_pi_only and not self.pi_settings.get("push_enabled", True):
            print(f"[Apexion] push suppressed by server settings: "
                  + "; ".join(f"{h['id']}({h['severity']})" for h in warn_hits))
            return

        report_payload = {
            "client_id": getattr(manager_client, "CLIENT_ID", ""),
            "provider":  meta.get("provider", ""),
            "path":      meta.get("path", ""),
            "action":    "warn",
            "hits": [_pub(h) for h in warn_hits],
            "prompt": meta.get("prompt", ""),
        }
        notify(title, body, report_payload=report_payload)
        print(f"[Apexion] warn notified: "
              + "; ".join(f"{h['id']}({h['severity']})" for h in warn_hits))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run_proxy():
    # Must receive a valid .policy_cache.json from the manager server before
    # starting the proxy (if a server is configured). Blocks/polls until ready.
    manager_client.ensure_initial_config()
    manager_client.start_background_poller()

    # Run the tool inventory scan once at startup, then every 10 minutes
    def _scan_and_report():
        try:
            print("[Apexion] scanning client tools and NHIs…")
            scan_data = tool_scanner.scan()
            tools = scan_data.get("tools", [])
            nhis = scan_data.get("nhis", [])
            print(f"[Apexion] found {len(tools)} tools and {len(nhis)} NHIs — reporting to server")
            manager_client.report_tools(tools, nhis)
        except Exception as e:
            print(f"[Apexion] tool scan error: {e}")

    def _periodic_scan():
        import time as _time
        _scan_and_report()
        while True:
            _time.sleep(600)   # re-scan every 10 minutes
            _scan_and_report()

    threading.Thread(target=_periodic_scan, daemon=True).start()

    start_report_server()
    opts = Options(listen_host="0.0.0.0", listen_port=8080)
    master = DumpMaster(opts)
    master.addons.add(ApexionAddon())
    print("[Apexion] proxy on 0.0.0.0:8080")
    print(f"[Apexion] DEBUG_ALL_POSTS={DEBUG_ALL_POSTS}")
    await master.run()

if __name__ == "__main__":
    asyncio.run(run_proxy())