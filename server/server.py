"""
server.py — Apexion/Vigil manager server (Flask)

Minimal, no-color, no-JS-framework UI. Two surfaces:

  1. Client API  (token-authenticated via X-Apexion-Token header, from clients' .env)
       POST /api/checkin        — client heartbeat / registration
       GET  /api/config         — returns current presidio_policy.json + version
       GET  /api/pi_settings    — returns this client's prompt-injection settings
       POST /api/report/dlp     — Apexion DLP hit report
       POST /api/report/pi      — Vigil prompt-injection hit report

  2. Manager web UI (session-login via username/password)
       GET  /login, /logout
       GET  /                   — redirects to /apexion
       GET  /apexion            — DLP attempt reports dashboard
       GET  /vigil              — prompt-injection attempt reports dashboard
       GET  /settings           — global DLP config editor + per-client PI settings

Run:
    pip install flask
    python3 server.py

Config (env vars, see .env.example):
    API_TOKEN     — shared secret clients must send in X-Apexion-Token
    SECRET_KEY    — Flask session secret
    HOST / PORT   — bind address (default 0.0.0.0:9000)
"""

import json
import os
import time
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, jsonify, session, redirect, url_for,
    render_template, flash,
)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import db
from policy_defaults import merge_policy, overrides_from, auto_meta, ACTIONS, SEVERITIES, ENTITY_LAYER, DEFAULT_LAYER
import teach_store
from teach_routes import build_blueprint

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

API_TOKEN  = os.environ.get("API_TOKEN", "change-me-token")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-secret")
HOST       = os.environ.get("HOST", "0.0.0.0")
PORT       = int(os.environ.get("PORT", "9000"))

app = Flask(__name__)
app.secret_key = SECRET_KEY

db.init_db()
teach_store.init_db()


@app.template_filter("datetimeformat")
def datetimeformat(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def require_api_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Apexion-Token", "")
        if token != API_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


app.register_blueprint(build_blueprint(login_required, require_api_token))


# ─────────────────────────────────────────────────────────────────────────────
# Manager web UI — login / logout
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return redirect(url_for("overview_dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    # First-run: no users exist yet -> create the first admin account
    first_run = not db.any_users_exist()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if first_run:
            if not username or not password:
                flash("Username and password required.")
                return redirect(url_for("login"))
            db.create_user(username, generate_password_hash(password))
            session["user"] = username
            return redirect(url_for("index"))

        user = db.get_user(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user"] = username
            return redirect(url_for("index"))
        flash("Invalid username or password.")
        return redirect(url_for("login"))

    return render_template("login.html", first_run=first_run)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────────────────────
# Manager web UI — dashboards
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/overview")
@login_required
def overview_dashboard():
    stats = db.get_overview_stats()
    return render_template("overview.html", active="overview", stats=stats)


@app.route("/apexion")
@login_required
def apexion_dashboard():
    stats = db.get_apexion_stats()
    client_filter = request.args.get("client", "")
    reports = db.list_dlp_reports(limit=300, client_id=client_filter or None)
    clients = db.list_clients()
    return render_template(
        "apexion.html",
        reports=reports,
        clients=clients,
        client_filter=client_filter,
        active="apexion",
        stats=stats
    )


@app.route("/vigil")
@login_required
def vigil_dashboard():
    tool_scans = db.get_tool_scans()
    client_filter = request.args.get("client", "")
    reports = db.list_pi_reports(limit=300, client_id=client_filter or None)
    clients = db.list_clients()
    return render_template(
        "vigil.html",
        active="vigil",
        tool_scans=tool_scans,
        reports=reports,
        clients=clients,
        client_filter=client_filter,
    )




def _recognizers_version() -> int:
    """Recognizer table has no own version counter; use MAX(updated_at) turned
    into an integer so any create/edit/delete/toggle changes this number."""
    recs = db.list_custom_recognizers()
    if not recs:
        return 0
    return int(max(r["updated_at"] for r in recs) * 1000)


def _effective_config_version(cfg_version: int) -> int:
    return cfg_version * 10_000_000 + (_recognizers_version() % 10_000_000)


def _full_policy(stored_json: str):
    """Policy over defaults UNION entities auto-discovered by clients' Presidio engines."""
    pol = merge_policy(json.loads(stored_json))
    catalog = {c["entity"]: c for c in db.get_entity_catalog()}
    for name, c in catalog.items():
        if name not in pol["entities"]:
            pol["entities"][name] = auto_meta(name, ", ".join(c["layers"]))
    return pol, catalog


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        form_type = request.form.get("form_type")

        if form_type in ("dlp_config", "dlp_reset"):
            if form_type == "dlp_reset":
                new_version = db.set_dlp_config(json.dumps({"entities": {}, "deny_list": []}))
                db.log_audit(session.get("user", "admin"), "policy_reset",
                             "Reset detection policy to built-in defaults", config_version=new_version)
                flash("Detection policy reset to built-in defaults. Clients will refresh automatically.")
                return redirect(url_for("settings"))
            try:
                pol, _cat = _full_policy(json.dumps({}))
                for name, cur in pol["entities"].items():
                    act = request.form.get(f"action__{name}", cur["action"])
                    sev = request.form.get(f"severity__{name}", cur["severity"])
                    if act not in ACTIONS or sev not in SEVERITIES:
                        raise ValueError(f"invalid value for {name}")
                    cur["action"], cur["severity"] = act, sev
                thr = float(request.form.get("score_threshold", "0.5"))
                if not 0 <= thr <= 1:
                    raise ValueError("score threshold must be between 0 and 1")
                pol["score_threshold"] = thr
                pol["deny_list"] = [t.strip() for t in request.form.get("deny_list", "").splitlines() if t.strip()]
            except Exception as e:
                flash(f"Invalid detection policy: {e}")
                return redirect(url_for("settings"))
            changed = {n: m for n, m in pol["entities"].items()
                       if request.form.get(f"action__{n}") or request.form.get(f"severity__{n}")}
            new_version = db.set_dlp_config(json.dumps(overrides_from(pol)))
            db.log_audit(session.get("user", "admin"), "policy_saved",
                         f"Saved detection policy — threshold {pol['score_threshold']}, "
                         f"{len(pol['deny_list'])} deny-list term(s)",
                         detail={"score_threshold": pol["score_threshold"], "deny_list": pol["deny_list"]},
                         config_version=new_version)
            flash(f"Detection policy saved (version {new_version}). Clients will refresh automatically.")
            return redirect(url_for("settings"))

        if form_type == "pi_settings":
            client_id = request.form.get("client_id", "")
            push_enabled  = 1 if request.form.get("push_enabled") == "on" else 0
            block_enabled = 1 if request.form.get("block_enabled") == "on" else 0
            warn_enabled  = 1 if request.form.get("warn_enabled") == "on" else 0
            db.set_pi_settings(client_id, push_enabled, block_enabled, warn_enabled)
            flash(f"Prompt-injection settings updated for {client_id}.")
            return redirect(url_for("settings"))

    cfg = db.get_dlp_config()
    policy, catalog = _full_policy(cfg["patterns_json"])
    recognizers = db.list_custom_recognizers()
    admin_entities = {r["entity"] for r in recognizers}
    groups = {}
    for name, m in policy["entities"].items():
        if name in admin_entities:
            continue   # shown in its own "Custom recognizers" section instead
        c = catalog.get(name)
        layer = " + ".join(c["layers"]) if c else ENTITY_LAYER.get(name, DEFAULT_LAYER) + " (no client has reported yet)"
        groups.setdefault(m["category"], []).append(dict(m, name=name, layer=layer,
                                                        recognizers=", ".join(c["recognizers"]) if c else ""))
    clients = db.list_clients()
    pi_settings_map = {c["client_id"]: db.get_pi_settings(c["client_id"]) for c in clients}
    audit_log = db.list_audit_log(30)

    return render_template(
        "settings.html",
        policy=policy,
        catalog_count=len(catalog),
        groups=groups,
        recognizers=recognizers,
        audit_log=audit_log,
        actions=ACTIONS,
        severities=SEVERITIES,
        config_version=cfg["version"],
        config_updated_at=cfg["updated_at"],
        clients=clients,
        pi_settings_map=pi_settings_map,
        active="settings",
    )











# ─────────────────────────────────────────────────────────────────────────────
# Client API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/checkin", methods=["POST"])
@require_api_token
def api_checkin():
    body = request.get_json(silent=True) or {}
    client_id = body.get("client_id", "").strip()
    name      = body.get("name", client_id).strip() or client_id
    if not client_id:
        return jsonify({"error": "client_id required"}), 400

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    db.upsert_client(client_id, name, ip)

    cfg = db.get_dlp_config()
    pi  = db.get_pi_settings(client_id)

    return jsonify({
        "ok": True,
        "server_time": time.time(),
        "config_version": _effective_config_version(cfg["version"]),
        "custom_version": teach_store.max_config_version(),
        "pi_settings": {
            "push_enabled":  bool(pi["push_enabled"]),
            "block_enabled": bool(pi["block_enabled"]),
            "warn_enabled":  bool(pi["warn_enabled"]),
        },
    })


@app.route("/api/config", methods=["GET"])
@require_api_token
def api_config():
    """Clients poll this. If their cached version != server version, they
    download the new Presidio policy and restart."""
    client_id = request.args.get("client_id", "").strip()
    cfg = db.get_dlp_config()

    eff_version = _effective_config_version(cfg["version"])
    if client_id:
        db.set_client_config_version(client_id, eff_version)

    policy = json.loads(cfg["patterns_json"])
    policy["custom_recognizers"] = [
        {k: r[k] for k in ("id", "name", "entity", "kind", "pattern", "context",
                            "label", "category", "severity", "action", "enabled")}
        for r in db.list_custom_recognizers(enabled_only=False)
    ]

    return jsonify({
        "version": eff_version,
        "policy": policy,
        "updated_at": cfg["updated_at"],
        "custom_version": teach_store.max_config_version(),
    })


# ── Custom recognizer admin API (no-code recognizer builder) ────────────────

import re as _re
import uuid as _uuid


def _validate_regex(pattern: str) -> str | None:
    try:
        _re.compile(pattern)
    except _re.error as e:
        return str(e)
    return None


def _validate_recognizer_payload(data: dict) -> str | None:
    name = (data.get("name") or "").strip()
    entity = (data.get("entity") or "").strip().upper()
    kind = data.get("kind")
    label = (data.get("label") or "").strip()
    category = data.get("category")
    severity = data.get("severity")
    action = data.get("action")
    if not name:
        return "name is required"
    if not entity or not _re.match(r"^[A-Z][A-Z0-9_]*$", entity):
        return "entity must be an uppercase identifier, e.g. EMPLOYEE_ID"
    if kind not in ("regex", "deny_list"):
        return "kind must be 'regex' or 'deny_list'"
    if not label:
        return "label is required"
    if severity not in SEVERITIES:
        return f"severity must be one of {SEVERITIES}"
    if action not in ACTIONS:
        return f"action must be one of {ACTIONS}"
    if not category:
        return "category is required"
    if kind == "regex":
        pat = (data.get("pattern") or {}).get("regex", "")
        if not pat:
            return "regex pattern is required"
        err = _validate_regex(pat)
        if err:
            return f"invalid regex: {err}"
        score = (data.get("pattern") or {}).get("score", 0.75)
        if not isinstance(score, (int, float)) or not 0 < score <= 1:
            return "regex score must be between 0 (exclusive) and 1"
    else:
        terms = (data.get("pattern") or {}).get("terms", [])
        if not isinstance(terms, list) or not terms:
            return "deny_list needs at least one term"
    ctx = data.get("context", [])
    if not isinstance(ctx, list):
        return "context must be a list of words"
    return None


@app.route("/api/admin/recognizers", methods=["GET"])
@login_required
def api_list_recognizers():
    return jsonify({"recognizers": db.list_custom_recognizers()})


@app.route("/api/admin/recognizers", methods=["POST"])
@login_required
def api_create_recognizer():
    data = request.get_json(silent=True) or {}
    err = _validate_recognizer_payload(data)
    if err:
        return jsonify({"error": err}), 400
    rid = data.get("id") or _uuid.uuid4().hex[:12]
    if db.get_custom_recognizer(rid):
        return jsonify({"error": "a recognizer with this id already exists"}), 409
    entity = data["entity"].strip().upper()
    db.upsert_custom_recognizer(
        rid, name=data["name"].strip(), entity=entity, kind=data["kind"],
        pattern=data.get("pattern") or {}, context=data.get("context") or [],
        label=data["label"].strip(), category=data["category"], severity=data["severity"],
        action=data["action"], enabled=bool(data.get("enabled", True)),
        actor=session.get("user", "admin"))
    db.log_audit(session.get("user", "admin"), "recognizer_created",
                 f"Created recognizer '{data['name']}' ({entity})", detail={"id": rid, **data})
    return jsonify({"ok": True, "id": rid}), 201


@app.route("/api/admin/recognizers/<rid>", methods=["PUT"])
@login_required
def api_update_recognizer(rid):
    if not db.get_custom_recognizer(rid):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    err = _validate_recognizer_payload(data)
    if err:
        return jsonify({"error": err}), 400
    entity = data["entity"].strip().upper()
    db.upsert_custom_recognizer(
        rid, name=data["name"].strip(), entity=entity, kind=data["kind"],
        pattern=data.get("pattern") or {}, context=data.get("context") or [],
        label=data["label"].strip(), category=data["category"], severity=data["severity"],
        action=data["action"], enabled=bool(data.get("enabled", True)),
        actor=session.get("user", "admin"))
    db.log_audit(session.get("user", "admin"), "recognizer_updated",
                 f"Updated recognizer '{data['name']}' ({entity})", detail={"id": rid, **data})
    return jsonify({"ok": True})


@app.route("/api/admin/recognizers/<rid>", methods=["DELETE"])
@login_required
def api_delete_recognizer(rid):
    rec = db.get_custom_recognizer(rid)
    if not rec:
        return jsonify({"error": "not found"}), 404
    db.delete_custom_recognizer(rid)
    db.log_audit(session.get("user", "admin"), "recognizer_deleted",
                 f"Deleted recognizer '{rec['name']}' ({rec['entity']})", detail={"id": rid})
    return jsonify({"ok": True})


@app.route("/api/admin/recognizers/<rid>/toggle", methods=["POST"])
@login_required
def api_toggle_recognizer(rid):
    rec = db.get_custom_recognizer(rid)
    if not rec:
        return jsonify({"error": "not found"}), 404
    new_state = not rec["enabled"]
    db.set_custom_recognizer_enabled(rid, new_state)
    db.log_audit(session.get("user", "admin"), "recognizer_toggled",
                 f"{'Enabled' if new_state else 'Disabled'} recognizer '{rec['name']}'",
                 detail={"id": rid, "enabled": new_state})
    return jsonify({"ok": True, "enabled": new_state})


@app.route("/api/admin/recognizers/test", methods=["POST"])
@login_required
def api_test_recognizer():
    """Instant feedback while building a recognizer — runs the regex or
    deny-list match server-side against sample text, WITHOUT needing a client
    connected. This is a lightweight approximation (no NLP context boost —
    that only happens on a real client with the full Presidio pipeline) but
    catches the two most common authoring mistakes: a regex that doesn't
    match the intended sample, or one that's so loose it matches everything.
    """
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    sample = data.get("sample_text", "") or ""
    if not sample.strip():
        return jsonify({"error": "sample_text is required"}), 400
    matches = []
    if kind == "regex":
        pat = (data.get("pattern") or {}).get("regex", "")
        err = _validate_regex(pat)
        if err:
            return jsonify({"error": f"invalid regex: {err}"}), 400
        try:
            for m in _re.finditer(pat, sample):
                matches.append({"text": m.group(0), "start": m.start(), "end": m.end()})
                if len(matches) >= 20:
                    break
        except _re.error as e:
            return jsonify({"error": f"regex error: {e}"}), 400
    elif kind == "deny_list":
        terms = (data.get("pattern") or {}).get("terms", [])
        low = sample.lower()
        for t in terms:
            i = low.find(str(t).lower())
            if i >= 0:
                matches.append({"text": sample[i:i + len(t)], "start": i, "end": i + len(t)})
    else:
        return jsonify({"error": "kind must be 'regex' or 'deny_list'"}), 400
    warning = None
    if kind == "regex" and len(sample) > 20 and len(matches) and sum(len(m["text"]) for m in matches) > 0.8 * len(sample):
        warning = "This pattern matches most of the sample text — it may be too broad for real traffic."
    return jsonify({"matches": matches, "count": len(matches), "warning": warning})


@app.route("/api/admin/audit_log", methods=["GET"])
@login_required
def api_audit_log():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify({"entries": db.list_audit_log(limit)})


@app.route("/api/pi_settings", methods=["GET"])
@require_api_token
def api_pi_settings():
    client_id = request.args.get("client_id", "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400
    pi = db.get_pi_settings(client_id)
    return jsonify({
        "push_enabled":  bool(pi["push_enabled"]),
        "block_enabled": bool(pi["block_enabled"]),
        "warn_enabled":  bool(pi["warn_enabled"]),
    })


@app.route("/api/report/catalog", methods=["POST"])
@require_api_token
def api_report_catalog():
    data = request.get_json(silent=True) or {}
    ents = data.get("entities")
    if not isinstance(ents, list):
        return jsonify({"error": "entities must be a list"}), 400
    db.upsert_entity_catalog(ents[:500])
    return jsonify({"ok": True, "count": len(ents)})


@app.route("/api/report/dlp", methods=["POST"])
@require_api_token
def api_report_dlp():
    body = request.get_json(silent=True) or {}
    client_id = body.get("client_id", "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400

    client = db.get_client(client_id)
    client_name = client["name"] if client else client_id

    db.insert_dlp_report(
        client_id=client_id,
        client_name=client_name,
        provider=body.get("provider", ""),
        path=body.get("path", ""),
        worst_action=body.get("worst_action", ""),
        hits=body.get("hits", []),
        prompt=body.get("prompt", ""),
    )
    return jsonify({"ok": True})


@app.route("/api/report/pi", methods=["POST"])
@require_api_token
def api_report_pi():
    body = request.get_json(silent=True) or {}
    client_id = body.get("client_id", "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400

    client = db.get_client(client_id)
    client_name = client["name"] if client else client_id

    db.insert_pi_report(
        client_id=client_id,
        client_name=client_name,
        provider=body.get("provider", ""),
        path=body.get("path", ""),
        action=body.get("action", ""),
        score=body.get("score"),
        hits=body.get("hits", []),
        prompt=body.get("prompt", ""),
    )
    return jsonify({"ok": True})


@app.route("/api/report/tools", methods=["POST"])
@require_api_token
def api_report_tools():
    body = request.get_json(silent=True) or {}
    client_id = body.get("client_id", "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400

    client = db.get_client(client_id)
    client_name = body.get("client_name") or (client["name"] if client else client_id)
    tools = body.get("tools", [])
    nhis = body.get("nhis", [])
    if not isinstance(tools, list):
        return jsonify({"error": "tools must be a list"}), 400

    db.upsert_tool_scan(client_id, client_name, tools, nhis)
    return jsonify({"ok": True, "tools_stored": len(tools), "nhis_stored": len(nhis)})


# ───────────────────────────────────────────────────────────────────────────────
# Entry point
# ───────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[Server] Apexion/Vigil manager on {HOST}:{PORT}")
    print(f"[Server] API_TOKEN={'<default - CHANGE ME>' if API_TOKEN == 'change-me-token' else '<set>'}")
    app.run(host=HOST, port=PORT, debug=False)
