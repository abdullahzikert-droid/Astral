"""teach_store.py — persistence for taught (custom) DLP detectors.

Uses the same apexion_server.db as db.py (own tables, own functions) so
there's a single DB file to back up, matching the rest of the server.
"""
from __future__ import annotations

import json
import time
import uuid

import db as _db
from teach_engine import Detector

_CACHE: dict[str, Detector] = {}


def init_db():
    conn = _db.get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS custom_detectors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            examples TEXT NOT NULL,
            surfaces TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'redact',
            severity TEXT NOT NULL DEFAULT 'high',
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'learning',
            training INTEGER NOT NULL DEFAULT 0,
            accuracy REAL,
            report_json TEXT,
            model BLOB,
            created_at REAL NOT NULL,
            config_version INTEGER NOT NULL DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS custom_questions (
            id TEXT PRIMARY KEY,
            detector_id TEXT NOT NULL,
            client_id TEXT,
            context TEXT NOT NULL,
            value TEXT NOT NULL,
            confidence REAL NOT NULL,
            ts REAL NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cq_open ON custom_questions(detector_id, resolved)")
    conn.commit()
    conn.close()


def slugify(name: str) -> str:
    out = "".join(ch if ch.isalnum() else "_" for ch in name.upper()).strip("_")
    while "__" in out:
        out = out.replace("__", "_")
    return out or "CUSTOM"


def _next_version(conn) -> int:
    row = conn.execute("SELECT COALESCE(MAX(config_version), 0) AS v FROM custom_detectors").fetchone()
    return (row["v"] or 0) + 1


def create(name: str, examples: list[str], surfaces: list[str], action: str, severity: str = "high") -> str:
    did = slugify(name) + "_" + uuid.uuid4().hex[:6]
    conn = _db.get_db()
    conn.execute(
        "INSERT INTO custom_detectors (id,name,examples,surfaces,action,severity,created_at,config_version) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (did, name, json.dumps(examples), json.dumps(surfaces), action, severity, time.time(), _next_version(conn)),
    )
    conn.commit()
    conn.close()
    return did


def save_model(did: str, det: Detector, status: str = "ready") -> None:
    rep = det.report
    conn = _db.get_db()
    conn.execute(
        "UPDATE custom_detectors SET model=?, status=?, training=0, accuracy=?, report_json=?, examples=?, config_version=? WHERE id=?",
        (det.dumps(), status, None if rep is None else rep.accuracy,
         None if rep is None else json.dumps(rep.__dict__), json.dumps(det.examples), _next_version(conn), did),
    )
    conn.commit()
    conn.close()
    _CACHE[did] = det


def mark_training(did: str) -> None:
    """Retrain-in-place (improve/answer): keep the current model serving
    (status stays 'ready') but flag that a new one is on the way, so the
    UI/pollers can show 'Astral is learning…' without taking protection offline."""
    conn = _db.get_db()
    conn.execute("UPDATE custom_detectors SET training=1 WHERE id=?", (did,))
    conn.commit()
    conn.close()


def mark_failed(did: str, error: str) -> None:
    conn = _db.get_db()
    # Only first-time training failures flip status to 'failed'; a failed RETRAIN
    # of an already-ready detector just clears the training flag and keeps serving
    # the last good model — a transient error shouldn't take protection offline.
    conn.execute(
        "UPDATE custom_detectors SET training=0, status=(CASE WHEN status='ready' THEN 'ready' ELSE 'failed' END), "
        "report_json=? WHERE id=?",
        (json.dumps({"error": error[:200]}), did),
    )
    conn.commit()
    conn.close()


def get_row(did: str):
    conn = _db.get_db()
    row = conn.execute("SELECT * FROM custom_detectors WHERE id=?", (did,)).fetchone()
    conn.close()
    return row


def list_rows():
    conn = _db.get_db()
    rows = conn.execute("SELECT * FROM custom_detectors ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows


def get_detector(did: str) -> Detector | None:
    if did in _CACHE:
        return _CACHE[did]
    row = get_row(did)
    if row is None or row["model"] is None:
        return None
    try:
        det = Detector.loads(row["model"])
    except Exception as exc:  # noqa: BLE001 - tampered/corrupt blob: skip it, never crash a request
        print(f"[teach] refusing to load detector {did}: {exc}")
        return None
    _CACHE[did] = det
    return det


def ready_enabled() -> list[tuple]:
    out = []
    for row in list_rows():
        if row["enabled"] and row["status"] == "ready":
            det = get_detector(row["id"])
            if det is not None:
                out.append((row, det))
    return out


def set_enabled(did: str, enabled: bool) -> None:
    conn = _db.get_db()
    conn.execute("UPDATE custom_detectors SET enabled=?, config_version=? WHERE id=?",
                 (int(enabled), _next_version(conn), did))
    conn.commit()
    conn.close()


def set_action(did: str, action: str) -> None:
    """Update the enforcement action. This must also patch the ALREADY-TRAINED
    model's baked-in `action` attribute and re-save it — the model blob is what
    ships to clients, so if only the DB row changed, every client would keep
    enforcing the old action until its next full retrain (which may be days away,
    or never, if nobody adds examples)."""
    det = get_detector(did)
    conn = _db.get_db()
    conn.execute("UPDATE custom_detectors SET action=?, config_version=? WHERE id=?",
                 (action, _next_version(conn), did))
    conn.commit()
    conn.close()
    if det is not None:
        det.action = action
        # save_model bumps config_version again and updates the stored blob;
        # status stays whatever it already was ('ready' in the normal case).
        row = get_row(did)
        save_model(did, det, status=row["status"] if row else "ready")


def delete(did: str) -> None:
    conn = _db.get_db()
    conn.execute("DELETE FROM custom_detectors WHERE id=?", (did,))
    conn.execute("DELETE FROM custom_questions WHERE detector_id=?", (did,))
    conn.commit()
    conn.close()
    _CACHE.pop(did, None)


def max_config_version() -> int:
    conn = _db.get_db()
    row = conn.execute("SELECT COALESCE(MAX(config_version), 0) AS v FROM custom_detectors").fetchone()
    conn.close()
    return row["v"] or 0


def ready_manifest() -> list[dict]:
    """What clients pull: enabled+ready detectors' signed model blobs, base64-free (Flask jsonify handles bytes via hex)."""
    import base64
    out = []
    for row, _det in ready_enabled():
        out.append({
            "id": row["id"], "name": row["name"], "action": row["action"], "severity": row["severity"],
            "model_b64": base64.b64encode(row["model"]).decode("ascii"),
        })
    return out


# ---- uncertain queue -----------------------------------------------------

def queue_question(did: str, client_id: str | None, context: str, value: str, confidence: float) -> str | None:
    conn = _db.get_db()
    dup = conn.execute("SELECT id FROM custom_questions WHERE detector_id=? AND value=? AND resolved=0",
                        (did, value)).fetchone()
    if dup:
        conn.close()
        return None
    qid = uuid.uuid4().hex[:12]
    conn.execute(
        "INSERT INTO custom_questions (id,detector_id,client_id,context,value,confidence,ts) VALUES (?,?,?,?,?,?,?)",
        (qid, did, client_id, context, value, confidence, time.time()),
    )
    conn.commit()
    conn.close()
    return qid


def open_questions(limit: int = 50):
    conn = _db.get_db()
    rows = conn.execute(
        "SELECT q.*, d.name AS detector_name FROM custom_questions q JOIN custom_detectors d ON d.id=q.detector_id "
        "WHERE q.resolved=0 ORDER BY ABS(q.confidence-0.5) ASC, q.ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def get_question(qid: str):
    conn = _db.get_db()
    row = conn.execute("SELECT * FROM custom_questions WHERE id=?", (qid,)).fetchone()
    conn.close()
    return row


def resolve_question(qid: str) -> None:
    conn = _db.get_db()
    conn.execute("UPDATE custom_questions SET resolved=1 WHERE id=?", (qid,))
    conn.commit()
    conn.close()
