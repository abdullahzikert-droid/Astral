"""teach_routes.py — 'Teach Astral' HTTP surface, wired into the Apexion server.

Two audiences, same blueprint:
  Admin UI   (login_required, session auth)   /teach, /teach/api/*
  Client API (X-Apexion-Token, like the rest) /api/custom/manifest, /api/custom/question

build_blueprint() takes the two decorators from server.py instead of importing
server.py directly, to avoid a circular import (server.py registers this blueprint).
"""
from __future__ import annotations

import json
import threading

from flask import Blueprint, jsonify, render_template, request

import teach_store as store
from teach_engine import Detector, SURFACES, mutate_negative, probe
import teach_extract

MAX_EXAMPLES = 200
MAX_EX_LEN = 120
ACTIONS = {"warn", "redact", "block"}
MAX_UPLOAD = 2_000_000


def build_blueprint(login_required, require_api_token) -> Blueprint:
    bp = Blueprint("teach", __name__)

    # ---------------------------------------------------------------- training
    def _train_job(did: str) -> None:
        row = store.get_row(did)
        if row is None:
            return
        # First-time training: status is already 'learning' from create().
        # Retrain (improve/answer): mark `training` without touching status,
        # so the CURRENT model keeps serving clients until the new one lands.
        if row["status"] == "ready":
            store.mark_training(did)
        try:
            det = Detector(did, row["name"], json.loads(row["examples"]), json.loads(row["surfaces"]),
                            row["action"], row["severity"])
            det.train()
            p = probe(det)
            det.report.accuracy, det.report.precision, det.report.recall = p.accuracy, p.precision, p.recall
            store.save_model(did, det, status="ready")
        except Exception as exc:  # noqa: BLE001 - surface as a friendly failed state, never crash the thread
            store.mark_failed(did, str(exc))

    def _train_bg(did: str) -> None:
        threading.Thread(target=_train_job, args=(did,), daemon=True).start()

    def _view(row, full=False) -> dict:
        rep = json.loads(row["report_json"]) if row["report_json"] else {}
        status = row["status"]
        out = {
            "id": row["id"], "name": row["name"],
            "protection": "on" if (row["enabled"] and status == "ready") else "off",
            "action": row["action"], "status": status, "training": bool(row["training"]),
            "state": ("Astral is learning…" if row["training"] else
                      {"learning": "Astral is learning…",
                       "ready": "Astral has learned to recognize this information.",
                       "failed": "Astral couldn't learn this yet. Try adding a few more examples."}[status]),
            "accuracy": None if row["accuracy"] is None else round(row["accuracy"] * 100),
            "warnings": rep.get("warnings", []),
        }
        if full:
            out["examples"] = json.loads(row["examples"])
            out["surfaces"] = json.loads(row["surfaces"])
            out["advanced"] = {k: rep.get(k) for k in ("precision", "recall", "n_train", "n_test", "used_shape")}
        return out

    # ---------------------------------------------------------------- admin UI
    @bp.route("/teach")
    @login_required
    def teach_page():
        return render_template("teach.html", active="teach")

    @bp.route("/teach/api/detectors", methods=["GET"])
    @login_required
    def list_detectors():
        return jsonify({"detectors": [_view(r) for r in store.list_rows()]})

    @bp.route("/teach/api/detectors", methods=["POST"])
    @login_required
    def create_detector():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        examples = list(dict.fromkeys(e.strip() for e in body.get("examples", []) if e and e.strip()))
        surfaces = [s for s in body.get("surfaces", list(SURFACES)) if s in SURFACES] or list(SURFACES)
        action = body.get("action", "redact")

        if len(name) < 2 or len(name) > 60:
            return jsonify({"error": "name must be 2-60 characters"}), 422
        if not examples:
            return jsonify({"error": "give at least one example"}), 422
        if len(examples) > MAX_EXAMPLES or any(len(e) > MAX_EX_LEN for e in examples):
            return jsonify({"error": "examples are too many or too long"}), 422
        if action not in ACTIONS:
            return jsonify({"error": "action must be warn, redact or block"}), 422

        did = store.create(name, examples, surfaces, action)
        _train_bg(did)
        return jsonify({"id": did, "state": "Astral is learning…"})

    @bp.route("/teach/api/detectors/<did>", methods=["GET"])
    @login_required
    def get_detector_view(did):
        row = store.get_row(did)
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(_view(row, full=True))

    @bp.route("/teach/api/detectors/<did>", methods=["DELETE"])
    @login_required
    def delete_detector(did):
        store.delete(did)
        return jsonify({"ok": True})

    @bp.route("/teach/api/detectors/<did>/enabled", methods=["POST"])
    @login_required
    def set_enabled(did):
        if store.get_row(did) is None:
            return jsonify({"error": "not found"}), 404
        body = request.get_json(silent=True) or {}
        store.set_enabled(did, bool(body.get("enabled")))
        return jsonify({"ok": True})

    @bp.route("/teach/api/detectors/<did>/action", methods=["POST"])
    @login_required
    def set_action(did):
        body = request.get_json(silent=True) or {}
        action = body.get("action")
        if action not in ACTIONS or store.get_row(did) is None:
            return jsonify({"error": "bad request"}), 400
        store.set_action(did, action)
        return jsonify({"ok": True})

    @bp.route("/teach/api/detectors/<did>/examples", methods=["POST"])
    @login_required
    def add_examples(did):
        """'Improve detection': teach more examples and retrain a copy in place;
        the live model keeps serving clients until the new one is saved."""
        det = store.get_detector(did)
        row = store.get_row(did)
        if det is None or row is None:
            return jsonify({"error": "still learning"}), 409
        body = request.get_json(silent=True) or {}
        new = list(dict.fromkeys(e.strip() for e in body.get("examples", []) if e and e.strip()))
        if not new or any(len(e) > MAX_EX_LEN for e in new):
            return jsonify({"error": "add at least one example, under 120 characters each"}), 422
        added = [e for e in new if e not in det.examples]
        if not added:
            return jsonify({"ok": True, "added": 0, "message": "Astral already knows those."})
        if len(det.examples) + len(added) > MAX_EXAMPLES:
            return jsonify({"error": "too many examples"}), 400

        merged = det.examples + added
        # Persist the appended examples FIRST so the background retrain (which re-reads
        # the row from the DB) sees them; the live model keeps serving in the meantime.
        import db as _db
        conn = _db.get_db()
        conn.execute("UPDATE custom_detectors SET examples=? WHERE id=?", (json.dumps(merged), did))
        conn.commit()
        conn.close()
        _train_bg(did)
        return jsonify({"ok": True, "added": len(added),
                         "message": f"Astral is learning from {len(added)} new example{'s' if len(added) != 1 else ''}."})

    @bp.route("/teach/api/detectors/<did>/check", methods=["POST"])
    @login_required
    def check_understanding(did):
        det = store.get_detector(did)
        row = store.get_row(did)
        if det is None or row is None:
            return jsonify({"error": "still learning"}), 409
        import random
        rng = random.Random()
        samples = []
        if det.shape is not None:
            samples.append({"text": det.shape.sample(rng), "is_match": True})
            for _ in range(2):
                samples.append({"text": mutate_negative(det.shape, rng), "is_match": False})
            samples.append({"text": row["name"].lower(), "is_match": False})
        rng.shuffle(samples)
        return jsonify({"samples": samples[:4]})

    @bp.route("/teach/api/extract", methods=["POST"])
    @login_required
    def extract_text():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        text = body.get("text") or ""
        if len(name) < 2 or not text.strip():
            return jsonify({"error": "name and text required"}), 422
        return jsonify(teach_extract.find_examples(text[:teach_extract.MAX_TEXT], name))

    @bp.route("/teach/api/extract/file", methods=["POST"])
    @login_required
    def extract_file():
        name = (request.form.get("name") or "").strip()
        f = request.files.get("file")
        if len(name) < 2:
            return jsonify({"error": "name required"}), 422
        if f is None:
            return jsonify({"error": "file required"}), 422
        raw = f.read(MAX_UPLOAD + 1)
        if len(raw) > MAX_UPLOAD:
            return jsonify({"error": "file too large"}), 413
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"error": "upload a plain-text, CSV or JSON file"}), 415
        return jsonify(teach_extract.find_examples(text, name))

    @bp.route("/teach/api/questions", methods=["GET"])
    @login_required
    def list_questions():
        rows = store.open_questions()
        return jsonify({"questions": [
            {"id": r["id"], "detector_id": r["detector_id"], "detector_name": r["detector_name"],
             "value": r["value"], "context": r["context"], "client_id": r["client_id"],
             "prompt": f"Could \"{r['value']}\" be your {r['detector_name']}?"}
            for r in rows
        ]})

    @bp.route("/teach/api/questions/<qid>/answer", methods=["POST"])
    @login_required
    def answer_question(qid):
        q = store.get_question(qid)
        if q is None or q["resolved"]:
            return jsonify({"error": "not found"}), 404
        det = store.get_detector(q["detector_id"])
        if det is None:
            return jsonify({"error": "still learning"}), 409
        body = request.get_json(silent=True) or {}
        is_match = bool(body.get("is_match"))
        ctx = q["context"]
        pos = ctx.find(q["value"])
        pos = pos if pos >= 0 else 0
        det.learn(ctx, pos, pos + len(q["value"]), is_match)
        store.resolve_question(qid)

        import db as _db
        conn = _db.get_db()
        conn.execute("UPDATE custom_detectors SET examples=? WHERE id=?", (json.dumps(det.examples), q["detector_id"]))
        conn.commit()
        conn.close()
        _train_bg(q["detector_id"])
        return jsonify({"ok": True, "message": "Thanks — Astral is learning from that."})

    # ---------------------------------------------------------------- client API
    @bp.route("/api/custom/manifest", methods=["GET"])
    @require_api_token
    def custom_manifest():
        """Clients poll this alongside /api/config. If config_version differs from
        their cached one, they download the (signed) model blobs in the response."""
        return jsonify({"version": store.max_config_version(), "detectors": store.ready_manifest()})

    @bp.route("/api/custom/question", methods=["POST"])
    @require_api_token
    def custom_question():
        """A client reports an uncertain candidate instead of enforcing it. Never
        blocks/redacts on the client's own judgement — a human answers via /teach."""
        body = request.get_json(silent=True) or {}
        did = body.get("detector_id", "")
        if not did or store.get_row(did) is None:
            return jsonify({"error": "unknown detector"}), 404
        qid = store.queue_question(did, body.get("client_id"), body.get("context", ""),
                                    body.get("value", ""), float(body.get("confidence", 0.5)))
        return jsonify({"ok": True, "queued": qid is not None})

    return bp
