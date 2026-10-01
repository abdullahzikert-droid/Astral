"""
db.py — SQLite schema + helpers for Apexion/Vigil manager server.

Tables:
  users          login accounts for the manager web UI
  clients        connected client machines (identified by client_id from .env)
  dlp_config     single-row table holding current dlp_patterns.json + version
  pi_settings    per-client prompt-injection settings (push on/off, block+warn)
  dlp_reports    DLP hit reports from clients (Apexion dashboard)
  pi_reports     prompt-injection hit reports from clients (Vigil dashboard)
"""

import json
import sqlite3
import time
from pathlib import Path

DB_FILE = Path(__file__).parent / "apexion_server.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            ip_address TEXT,
            config_version INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'online'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS dlp_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL,
            patterns_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS pi_settings (
            client_id TEXT PRIMARY KEY,
            push_enabled INTEGER NOT NULL DEFAULT 1,
            block_enabled INTEGER NOT NULL DEFAULT 1,
            warn_enabled INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (client_id) REFERENCES clients(client_id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS dlp_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            ts REAL NOT NULL,
            provider TEXT,
            path TEXT,
            worst_action TEXT,
            hits_json TEXT NOT NULL,
            prompt TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS pi_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            ts REAL NOT NULL,
            provider TEXT,
            path TEXT,
            action TEXT,
            score REAL,
            hits_json TEXT NOT NULL,
            prompt TEXT
        )
    """)

    # tool_scans — one row per client, upserted on each scan
    c.execute("""
        CREATE TABLE IF NOT EXISTS tool_scans (
            client_id   TEXT PRIMARY KEY,
            client_name TEXT NOT NULL,
            ts          REAL NOT NULL,
            tools_json  TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS custom_recognizers (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            entity          TEXT NOT NULL,
            kind            TEXT NOT NULL,           -- 'regex' | 'deny_list'
            pattern_json    TEXT NOT NULL,            -- {"regex": "...", "score": 0.8} or {"terms": [...]}
            context_json    TEXT NOT NULL DEFAULT '[]',
            label           TEXT NOT NULL,
            category        TEXT NOT NULL,
            severity        TEXT NOT NULL,
            action          TEXT NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 1,
            created_by      TEXT,
            created_at      REAL NOT NULL,
            updated_at      REAL NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS config_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL NOT NULL,
            actor       TEXT NOT NULL,
            action      TEXT NOT NULL,               -- e.g. 'policy_saved', 'recognizer_created', 'recognizer_deleted', 'policy_reset'
            summary     TEXT NOT NULL,                -- short human-readable description
            detail_json TEXT,                         -- optional structured before/after
            config_version INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS entity_catalog (
            entity          TEXT PRIMARY KEY,
            recognizers_json TEXT NOT NULL,
            layers_json     TEXT NOT NULL,
            last_seen       REAL NOT NULL
        )
    """)

    # Remove tables that only ever held fake seeded data
    c.execute("DROP TABLE IF EXISTS policies")
    c.execute("DROP TABLE IF EXISTS enforcement_points")

    # Schema migration: check if prompt column exists, if not add it
    try:
        c.execute("ALTER TABLE tool_scans ADD COLUMN nhi_json TEXT")
    except sqlite3.OperationalError:
        pass
    # Schema migration: check if prompt column exists, if not add it
    try:
        c.execute("ALTER TABLE dlp_reports ADD COLUMN prompt TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE pi_reports ADD COLUMN prompt TEXT")
    except sqlite3.OperationalError:
        pass

    conn.commit()

    # dlp_config stores only OVERRIDES of policy_defaults.DEFAULT_POLICY
    row = c.execute("SELECT version, patterns_json FROM dlp_config WHERE id = 1").fetchone()
    if not row:
        c.execute("INSERT INTO dlp_config (id, version, patterns_json, updated_at) VALUES (1, 1, ?, ?)",
                  (json.dumps({"entities": {}, "deny_list": []}), time.time()))
        conn.commit()
    else:
        try:
            stored = json.loads(row["patterns_json"])
            legacy = ("patterns" in stored) or ("default" in stored) or ("ignored_entities" in stored)
        except Exception:
            legacy = True
        if legacy:   # regex-era or first Presidio JSON shape -> reset to defaults
            c.execute("UPDATE dlp_config SET version = ?, patterns_json = ?, updated_at = ? WHERE id = 1",
                      (row["version"] + 1, json.dumps({"entities": {}, "deny_list": []}), time.time()))
            conn.commit()

    conn.close()


# ── dlp_config helpers ──────────────────────────────────────────────────────

def get_dlp_config(conn=None):
    own = conn is None
    conn = conn or get_db()
    row = conn.execute("SELECT version, patterns_json, updated_at FROM dlp_config WHERE id = 1").fetchone()
    if own:
        conn.close()
    return row


def set_dlp_config(patterns_json: str):
    conn = get_db()
    row = get_dlp_config(conn)
    new_version = (row["version"] if row else 0) + 1
    conn.execute(
        "UPDATE dlp_config SET version = ?, patterns_json = ?, updated_at = ? WHERE id = 1",
        (new_version, patterns_json, time.time()),
    )
    conn.commit()
    conn.close()
    return new_version


# ── client helpers ──────────────────────────────────────────────────────────

def upsert_client(client_id: str, name: str, ip_address: str):
    conn = get_db()
    now = time.time()
    existing = conn.execute("SELECT client_id FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE clients SET last_seen = ?, ip_address = ?, status = 'online', name = ? WHERE client_id = ?",
            (now, ip_address, name, client_id),
        )
    else:
        conn.execute(
            "INSERT INTO clients (client_id, name, first_seen, last_seen, ip_address, config_version, status) "
            "VALUES (?, ?, ?, ?, ?, 0, 'online')",
            (client_id, name, now, now, ip_address),
        )
        conn.execute(
            "INSERT OR IGNORE INTO pi_settings (client_id, push_enabled, block_enabled, warn_enabled) "
            "VALUES (?, 1, 1, 1)",
            (client_id,),
        )
    conn.commit()
    conn.close()


def set_client_config_version(client_id: str, version: int):
    conn = get_db()
    conn.execute("UPDATE clients SET config_version = ? WHERE client_id = ?", (version, client_id))
    conn.commit()
    conn.close()


def list_clients():
    conn = get_db()
    rows = conn.execute("SELECT * FROM clients ORDER BY name ASC").fetchall()
    conn.close()
    # Mark stale clients (no check-in in 90s) as offline for display
    now = time.time()
    out = []
    for r in rows:
        d = dict(r)
        if now - d["last_seen"] > 90:
            d["status"] = "offline"
        out.append(d)
    return out


def get_client(client_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ── pi_settings helpers ─────────────────────────────────────────────────────

def get_pi_settings(client_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM pi_settings WHERE client_id = ?", (client_id,)).fetchone()
    conn.close()
    if not row:
        return {"client_id": client_id, "push_enabled": 1, "block_enabled": 1, "warn_enabled": 1}
    return dict(row)


def set_pi_settings(client_id: str, push_enabled: int, block_enabled: int, warn_enabled: int):
    conn = get_db()
    conn.execute(
        "INSERT INTO pi_settings (client_id, push_enabled, block_enabled, warn_enabled) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(client_id) DO UPDATE SET push_enabled=?, block_enabled=?, warn_enabled=?",
        (client_id, push_enabled, block_enabled, warn_enabled,
         push_enabled, block_enabled, warn_enabled),
    )
    conn.commit()
    conn.close()


# ── report helpers ──────────────────────────────────────────────────────────

def insert_dlp_report(client_id, client_name, provider, path, worst_action, hits, prompt=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO dlp_reports (client_id, client_name, ts, provider, path, worst_action, hits_json, prompt) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (client_id, client_name, time.time(), provider, path, worst_action, json.dumps(hits), prompt),
    )
    conn.commit()
    conn.close()


def insert_pi_report(client_id, client_name, provider, path, action, score, hits, prompt=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO pi_reports (client_id, client_name, ts, provider, path, action, score, hits_json, prompt) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (client_id, client_name, time.time(), provider, path, action, score, json.dumps(hits), prompt),
    )
    conn.commit()
    conn.close()


def list_dlp_reports(limit=200, client_id=None):
    conn = get_db()
    if client_id:
        rows = conn.execute(
            "SELECT * FROM dlp_reports WHERE client_id = ? ORDER BY ts DESC LIMIT ?",
            (client_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM dlp_reports ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["hits"] = json.loads(d.pop("hits_json"))
        out.append(d)
    return out


def list_pi_reports(limit=200, client_id=None):
    conn = get_db()
    if client_id:
        rows = conn.execute(
            "SELECT * FROM pi_reports WHERE client_id = ? ORDER BY ts DESC LIMIT ?",
            (client_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM pi_reports ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["hits"] = json.loads(d.pop("hits_json"))
        out.append(d)
    return out


# ── user helpers ────────────────────────────────────────────────────────────

def get_user(username: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password_hash: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, time.time()),
    )
    conn.commit()
    conn.close()


def any_users_exist() -> bool:
    conn = get_db()
    row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    conn.close()
    return row is not None


# ── tool_scans helpers ───────────────────────────────────────────────────────

def upsert_tool_scan(client_id: str, client_name: str, tools: list, nhis: list = None) -> None:
    """Insert or replace the tool inventory for a client (one row per client)."""
    if nhis is None: nhis = []
    conn = get_db()
    conn.execute(
        """
        INSERT INTO tool_scans (client_id, client_name, ts, tools_json, nhi_json)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET
            client_name = excluded.client_name,
            ts          = excluded.ts,
            tools_json  = excluded.tools_json,
            nhi_json    = excluded.nhi_json
        """,
        (client_id, client_name, time.time(), json.dumps(tools), json.dumps(nhis)),
    )
    conn.commit()
    conn.close()


def get_tool_scans() -> list:
    """Return all tool scans, newest first, with tools parsed from JSON."""
    conn = get_db()
    rows = conn.execute(
        "SELECT client_id, client_name, ts, tools_json, nhi_json FROM tool_scans ORDER BY ts DESC"
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        try:
            nhis = json.loads(r["nhi_json"]) if r["nhi_json"] else []
        except Exception:
            nhis = []
        result.append({
            "client_id":   r["client_id"],
            "client_name": r["client_name"],
            "ts":          r["ts"],
            "tools":       json.loads(r["tools_json"]),
            "nhis":        nhis
        })
    return result

def get_threat_logs():
    conn = get_db()
    dlp = conn.execute("SELECT ts, worst_action, hits_json FROM dlp_reports ORDER BY ts DESC LIMIT 50").fetchall()
    pi = conn.execute("SELECT ts, action, hits_json FROM pi_reports ORDER BY ts DESC LIMIT 50").fetchall()
    conn.close()
    
    logs = []
    for r in dlp:
        try:
            hits = json.loads(r["hits_json"])
            desc = ", ".join(h.get("label", "") for h in hits) if hits else "DLP Violation"
            logs.append({"layer": "Signature/Regex", "description": desc, "action": r["worst_action"], "ts": r["ts"]})
        except Exception:
            pass
            
    for r in pi:
        try:
            hits = json.loads(r["hits_json"])
            desc = ", ".join(h.get("label", "") for h in hits) if hits else "Prompt Injection"
            logs.append({"layer": "AI Judge", "description": desc, "action": r["action"], "ts": r["ts"]})
        except Exception:
            pass
            
    logs.sort(key=lambda x: x["ts"], reverse=True)
    return logs[:50]

def get_apexion_stats():
    conn = get_db()
    rows = conn.execute("SELECT worst_action, hits_json FROM dlp_reports").fetchall()
    conn.close()
    
    analyzed = len(rows)
    blocked = 0
    redacted = 0
    allowed = 0
    trigger_counts = {}
    
    for r in rows:
        wa = r["worst_action"]
        if wa == "block": blocked += 1
        elif wa == "redact": redacted += 1
        else: allowed += 1
        
        try:
            hits = json.loads(r["hits_json"])
            for h in hits:
                cat = h.get("category", h.get("label", "Unknown"))
                trigger_counts[cat] = trigger_counts.get(cat, 0) + 1
        except Exception:
            pass
            
    top_triggers = [{"name": k, "count": v} for k, v in sorted(trigger_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    return {
        "analyzed": analyzed,
        "allowed": allowed,
        "redacted": redacted,
        "blocked": blocked,
        "top_triggers": top_triggers
    }

def get_overview_stats():
    conn = get_db()
    dlp = conn.execute("SELECT worst_action FROM dlp_reports").fetchall()
    pi = conn.execute("SELECT action FROM pi_reports").fetchall()
    conn.close()

    apexion = {"allowed": 0, "redacted": 0, "blocked": 0}
    vigil = {"allowed": 0, "blocked": 0}

    for r in dlp:
        wa = r["worst_action"]
        if wa == "block": apexion["blocked"] += 1
        elif wa == "redact": apexion["redacted"] += 1
        else: apexion["allowed"] += 1

    for r in pi:
        act = r["action"]
        if act == "block": vigil["blocked"] += 1
        else: vigil["allowed"] += 1

    total_invocations = len(dlp) + len(pi)
    data_redactions = apexion["redacted"]
    threats_blocked = apexion["blocked"] + vigil["blocked"]

    # Get recent threat logs for replay strip
    recent_logs = get_threat_logs()[:10]
    replay_texts = []
    import datetime
    for log in recent_logs:
        ts_str = datetime.datetime.fromtimestamp(log["ts"]).strftime("%H:%M:%S")
        lvl = "CRITICAL" if log["action"] == "block" else ("WARN" if log["action"] == "redact" else "ALERT")
        replay_texts.append(f"[{ts_str}] {lvl}: {log['description']} ({log['layer']})")
    
    if not replay_texts:
        replay_texts = ["[System] Monitoring active. No recent threats detected."]
        
    return {
        "apexion": apexion,
        "vigil": vigil,
        "total_invocations": total_invocations,
        "data_redactions": data_redactions,
        "threats_blocked": threats_blocked,
        "replay_text": " | ".join(replay_texts),
    }


def upsert_entity_catalog(entities: list):
    """Union of everything any client's Presidio engine reports it can intercept."""
    conn = get_db()
    now = time.time()
    for e in entities:
        name = str(e.get("entity", "")).strip()
        if not name:
            continue
        conn.execute(
            "INSERT INTO entity_catalog (entity, recognizers_json, layers_json, last_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(entity) DO UPDATE SET recognizers_json=excluded.recognizers_json, "
            "layers_json=excluded.layers_json, last_seen=excluded.last_seen",
            (name, json.dumps(e.get("recognizers", [])), json.dumps(e.get("layers", [])), now))
    conn.commit()
    conn.close()


def get_entity_catalog() -> list:
    conn = get_db()
    rows = conn.execute("SELECT entity, recognizers_json, layers_json, last_seen FROM entity_catalog ORDER BY entity").fetchall()
    conn.close()
    return [{"entity": r["entity"], "recognizers": json.loads(r["recognizers_json"]),
             "layers": json.loads(r["layers_json"]), "last_seen": r["last_seen"]} for r in rows]


# ── custom recognizers (admin-defined, no code) ─────────────────────────────

def list_custom_recognizers(enabled_only: bool = False) -> list:
    conn = get_db()
    q = "SELECT * FROM custom_recognizers"
    if enabled_only:
        q += " WHERE enabled = 1"
    q += " ORDER BY created_at"
    rows = conn.execute(q).fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r["id"], "name": r["name"], "entity": r["entity"], "kind": r["kind"],
            "pattern": json.loads(r["pattern_json"]), "context": json.loads(r["context_json"]),
            "label": r["label"], "category": r["category"], "severity": r["severity"],
            "action": r["action"], "enabled": bool(r["enabled"]),
            "created_by": r["created_by"], "created_at": r["created_at"], "updated_at": r["updated_at"],
        })
    return out


def get_custom_recognizer(rid: str):
    conn = get_db()
    r = conn.execute("SELECT * FROM custom_recognizers WHERE id = ?", (rid,)).fetchone()
    conn.close()
    if not r:
        return None
    return {"id": r["id"], "name": r["name"], "entity": r["entity"], "kind": r["kind"],
            "pattern": json.loads(r["pattern_json"]), "context": json.loads(r["context_json"]),
            "label": r["label"], "category": r["category"], "severity": r["severity"],
            "action": r["action"], "enabled": bool(r["enabled"]),
            "created_by": r["created_by"], "created_at": r["created_at"], "updated_at": r["updated_at"]}


def upsert_custom_recognizer(rid: str, *, name, entity, kind, pattern, context, label, category,
                              severity, action, enabled, actor):
    conn = get_db()
    now = time.time()
    existing = conn.execute("SELECT id, created_at FROM custom_recognizers WHERE id = ?", (rid,)).fetchone()
    created_at = existing["created_at"] if existing else now
    conn.execute(
        "INSERT INTO custom_recognizers (id, name, entity, kind, pattern_json, context_json, label, "
        "category, severity, action, enabled, created_by, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name, entity=excluded.entity, kind=excluded.kind, "
        "pattern_json=excluded.pattern_json, context_json=excluded.context_json, label=excluded.label, "
        "category=excluded.category, severity=excluded.severity, action=excluded.action, "
        "enabled=excluded.enabled, updated_at=excluded.updated_at",
        (rid, name, entity, kind, json.dumps(pattern), json.dumps(context), label, category,
         severity, action, 1 if enabled else 0, actor, created_at, now))
    conn.commit()
    conn.close()


def delete_custom_recognizer(rid: str):
    conn = get_db()
    conn.execute("DELETE FROM custom_recognizers WHERE id = ?", (rid,))
    conn.commit()
    conn.close()


def set_custom_recognizer_enabled(rid: str, enabled: bool):
    conn = get_db()
    conn.execute("UPDATE custom_recognizers SET enabled = ?, updated_at = ? WHERE id = ?",
                 (1 if enabled else 0, time.time(), rid))
    conn.commit()
    conn.close()


# ── audit log ────────────────────────────────────────────────────────────────

def log_audit(actor: str, action: str, summary: str, detail: dict = None, config_version: int = None):
    conn = get_db()
    conn.execute(
        "INSERT INTO config_audit_log (ts, actor, action, summary, detail_json, config_version) VALUES (?,?,?,?,?,?)",
        (time.time(), actor, action, summary, json.dumps(detail) if detail is not None else None, config_version))
    conn.commit()
    conn.close()


def list_audit_log(limit: int = 100) -> list:
    conn = get_db()
    rows = conn.execute(
        "SELECT ts, actor, action, summary, detail_json, config_version FROM config_audit_log "
        "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [{"ts": r["ts"], "actor": r["actor"], "action": r["action"], "summary": r["summary"],
             "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
             "config_version": r["config_version"]} for r in rows]
