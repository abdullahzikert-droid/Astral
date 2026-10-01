"""teach_client.py — runs 'Teach Astral' custom detectors on the client.

Mirrors DLPEngine's job, but for detectors the admin taught through the
manager server's UI instead of hand-written regex:

  - manager_client.fetch_custom_manifest() polls the server; if custom_version
    changed, each detector's signed model blob is written to custom_models/
    and (re)loaded here.
  - scan_hits(text) returns hits in the SAME shape as DLPEngine.scan()
    ({id,label,category,severity,action}), so apexion_addon.py can just
    extend its existing all_hits list — no changes to escalate()/worst_action().
  - Uncertain candidates are NEVER enforced client-side. They're reported to
    the server's uncertain-answer queue for a human to resolve.

teach_engine.Detector.loads() verifies an HMAC signature before unpickling,
so a corrupted or spoofed model file is refused, not executed. TEACH_MODEL_KEY
must match the value configured on the server (see .env.example).
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from teach_engine import Detector

BASE_DIR = Path(__file__).parent
MODELS_DIR = BASE_DIR / "custom_models"
STATE_FILE = BASE_DIR / ".custom_state.json"
CONTEXT_CHARS = 60


def _local_version() -> int:
    try:
        return json.loads(STATE_FILE.read_text()).get("version", 0)
    except Exception:
        return 0


def _save_local_version(version: int) -> None:
    try:
        STATE_FILE.write_text(json.dumps({"version": version}))
    except Exception as e:
        print(f"[TeachClient] could not save state: {e}")


class CustomDetectorEngine:
    def __init__(self):
        self._detectors: dict[str, dict] = {}  # id -> {"det": Detector, "action": str, "label": str, "severity": str}
        MODELS_DIR.mkdir(exist_ok=True)
        self.load_from_disk()

    def load_from_disk(self) -> None:
        loaded = {}
        for f in MODELS_DIR.glob("*.bin"):
            try:
                det = Detector.loads(f.read_bytes())
                loaded[det.id] = det
            except Exception as e:  # noqa: BLE001 - a bad/tampered blob is skipped, never executed
                print(f"[TeachClient] refusing to load {f.name}: {e}")
        self._detectors = loaded
        if loaded:
            print(f"[TeachClient] {len(loaded)} custom detector(s) loaded")

    def apply_manifest(self, manifest: dict) -> None:
        """manifest = {'version': int, 'detectors': [{id,name,action,severity,model_b64}, ...]}
        from GET /api/custom/manifest. Writes any changed/new model blobs to disk and reloads."""
        server_ids = set()
        for d in manifest.get("detectors", []):
            server_ids.add(d["id"])
            blob = base64.b64decode(d["model_b64"])
            path = MODELS_DIR / f"{d['id']}.bin"
            if path.exists() and path.read_bytes() == blob:
                continue
            path.write_bytes(blob)
        # remove local copies of detectors the server no longer serves (deleted/disabled)
        for f in MODELS_DIR.glob("*.bin"):
            if f.stem not in server_ids:
                f.unlink(missing_ok=True)
        _save_local_version(manifest.get("version", 0))
        self.load_from_disk()

    def redact(self, text: str) -> tuple[str, list[dict]]:
        """Scrub every 'redact'-action custom detector's confident hits from
        text, right to left so earlier spans' offsets stay valid."""
        hits: list[dict] = []
        for did, det in self._detectors.items():
            if det.action != "redact":
                continue
            spans = [c for c in det.scan(text) if c.status == "detected"]
            for c in sorted(spans, key=lambda c: c.start, reverse=True):
                text = text[:c.start] + f"[REDACTED:CUSTOM_{did}]" + text[c.end:]
                hits.append({"id": f"CUSTOM_{did}", "label": det.name, "category": "custom",
                              "severity": det.severity, "action": "redact"})
        return text, hits

    def scan_hits(self, text: str) -> tuple[list[dict], list[dict]]:
        """Returns (enforced_hits, uncertain_reports). uncertain_reports are
        {"detector_id", "context", "value", "confidence"} — send to the server,
        never enforce."""
        hits: list[dict] = []
        uncertain: list[dict] = []
        for did, det in self._detectors.items():
            for c in det.scan(text):
                if c.status == "detected":
                    hits.append({"id": f"CUSTOM_{did}", "label": det.name, "category": "custom",
                                  "severity": det.severity, "action": det.action,
                                  "score": round(c.confidence, 3),
                                  "proof": {"engine": "teach-astral", "layer": "Teach Astral custom detector",
                                            "recognizer": det.name, "score": round(c.confidence, 3),
                                            "explanation": "Admin-taught detector matched with high confidence",
                                            "stages": ["taught model scan (status=detected)"],
                                            "span": [c.start, c.end],
                                            "preview": (c.text[:2] + "*" * min(max(len(c.text) - 4, 0), 12) + c.text[-2:]) if len(c.text) > 4 else "*" * len(c.text)}})
                elif c.status == "uncertain":
                    left = text[max(0, c.start - CONTEXT_CHARS):c.start]
                    right = text[c.end:c.end + CONTEXT_CHARS]
                    uncertain.append({
                        "detector_id": did,
                        "context": f"{left}{c.text}{right}".replace("\n", " "),
                        "value": c.text,
                        "confidence": c.confidence,
                    })
        return hits, uncertain


def poll_and_apply(manager_client_module) -> CustomDetectorEngine | None:
    """One-shot helper: fetch the manifest via manager_client and apply it.
    Returns None if the manager server isn't configured (manager_client.ENABLED is False)."""
    if not manager_client_module.ENABLED:
        return None
    manifest = manager_client_module.fetch_custom_manifest()
    engine = CustomDetectorEngine()
    if manifest:
        engine.apply_manifest(manifest)
    return engine
