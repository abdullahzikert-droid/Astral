"""
manager_client.py — client-side link to the Apexion/Vigil manager server.

Responsibilities:
  - Read SERVER_URL / API_TOKEN / CLIENT_ID / CLIENT_NAME from .env
  - Check in with the server (registers this client, fetches config version
    + pi_settings)
  - Before starting the proxy: block until a valid .policy_cache.json has been
    fetched from the server at least once (writing it to .policy_cache.json).
    If the server is unreachable or has no config, poll with backoff.
  - Background thread: periodically poll /api/config. If the server's config
    version differs from the locally cached version, download the new
    .policy_cache.json, write it to disk, and re-exec this process so
    apexion_addon.py picks it up fresh.
  - Send DLP / prompt-injection hit reports to the server.

Nothing here is required for apexion_addon.py to keep working stand-alone —
if SERVER_URL is unset, all functions become no-ops and the addon behaves
exactly as before (using the local .policy_cache.json as-is).
"""

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import requests

# All client→server traffic MUST bypass the local Apexion proxy entirely —
# otherwise check-ins/config-fetch/reports get routed through mitmproxy
# itself (via HTTP_PROXY/HTTPS_PROXY env vars set for the system proxy),
# which can hang or loop back. trust_env=False ignores those env vars, and
# proxies={} forces a direct connection for every request.
_session = requests.Session()
_session.trust_env = False
_NO_PROXY = {"http": None, "https": None}

BASE_DIR          = Path(__file__).parent
DLP_POLICY_FILE = BASE_DIR / ".policy_cache.json"
CONFIG_STATE_FILE = BASE_DIR / ".config_state.json"

SERVER_URL  = os.environ.get("SERVER_URL", "").rstrip("/")   # e.g. http://1.2.3.4:9000
API_TOKEN   = os.environ.get("API_TOKEN", "")
CLIENT_ID   = os.environ.get("CLIENT_ID", "")
CLIENT_NAME = os.environ.get("CLIENT_NAME", CLIENT_ID)

POLL_INTERVAL_SECS         = int(os.environ.get("CONFIG_POLL_INTERVAL", "30"))
INITIAL_RETRY_BACKOFF_SECS = int(os.environ.get("CONFIG_RETRY_BACKOFF", "10"))
MAX_RETRY_BACKOFF_SECS     = 120

ENABLED = bool(SERVER_URL and API_TOKEN and CLIENT_ID)


def _headers():
    return {"X-Apexion-Token": API_TOKEN, "Content-Type": "application/json"}


def _local_config_version() -> int:
    try:
        return json.loads(CONFIG_STATE_FILE.read_text()).get("version", 0)
    except Exception:
        return 0


def _save_local_config_version(version: int):
    try:
        CONFIG_STATE_FILE.write_text(json.dumps({"version": version}))
    except Exception as e:
        print(f"[ManagerClient] could not save config state: {e}")


def _write_policy(policy: dict, version: int):
    DLP_POLICY_FILE.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    _save_local_config_version(version)
    print(f"[ManagerClient] .policy_cache.json updated to version {version}")


# ─────────────────────────────────────────────────────────────────────────────
# Check-in
# ─────────────────────────────────────────────────────────────────────────────

def checkin() -> Optional[dict]:
    """Register/heartbeat with the server. Returns the response JSON, or None
    on failure."""
    if not ENABLED:
        return None
    try:
        r = _session.post(
            f"{SERVER_URL}/api/checkin",
            headers=_headers(),
            json={"client_id": CLIENT_ID, "name": CLIENT_NAME},
            timeout=10,
            proxies=_NO_PROXY,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[ManagerClient] checkin failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Config fetch
# ─────────────────────────────────────────────────────────────────────────────

def fetch_config() -> Optional[dict]:
    """Fetch current config from server. Returns {'version':.., 'policy':..}
    or None on failure."""
    if not ENABLED:
        return None
    try:
        r = _session.get(
            f"{SERVER_URL}/api/config",
            headers=_headers(),
            params={"client_id": CLIENT_ID},
            timeout=10,
            proxies=_NO_PROXY,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[ManagerClient] fetch_config failed: {e}")
        return None


def ensure_initial_config():
    """Block at startup until a valid .policy_cache.json is on disk.

    If SERVER_URL is not configured, this is a no-op and the local
    .policy_cache.json (shipped with the client) is used as-is.

    If SERVER_URL IS configured, the client MUST receive a config from the
    server before starting the proxy. Poll with backoff until it does.
    """
    if not ENABLED:
        print("[ManagerClient] SERVER_URL/API_TOKEN/CLIENT_ID not set — "
              "running with local .policy_cache.json, no manager server.")
        return

    backoff = INITIAL_RETRY_BACKOFF_SECS
    while True:
        checkin()
        cfg = fetch_config()
        if cfg and "policy" in cfg:
            local_version = _local_config_version()
            if cfg["version"] != local_version or not DLP_POLICY_FILE.exists():
                _write_policy(cfg["policy"], cfg["version"])
            else:
                print(f"[ManagerClient] config already up to date "
                      f"(version {cfg['version']})")
            return

        print(f"[ManagerClient] no config from server yet — "
              f"retrying in {backoff}s …")
        time.sleep(backoff)
        backoff = min(backoff * 2, MAX_RETRY_BACKOFF_SECS)


# ─────────────────────────────────────────────────────────────────────────────
# Background poller — restarts process on config change
# ─────────────────────────────────────────────────────────────────────────────

def _poll_loop():
    while True:
        time.sleep(POLL_INTERVAL_SECS)
        checkin()
        cfg = fetch_config()
        if not cfg or "policy" not in cfg:
            continue

        local_version = _local_config_version()
        if cfg["version"] != local_version:
            print(f"[ManagerClient] new DLP config detected "
                  f"(local={local_version}, server={cfg['version']}) — "
                  f"writing and restarting process …")
            _write_policy(cfg["policy"], cfg["version"])
            _restart_process()


def _restart_process():
    """Full re-exec of this process so apexion_addon.py reloads the new
    .policy_cache.json from scratch."""
    print("[ManagerClient] restarting process now …")
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(sys.executable, [sys.executable] + sys.argv)


def start_background_poller():
    if not ENABLED:
        return
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    print(f"[ManagerClient] background config poller started "
          f"(every {POLL_INTERVAL_SECS}s)")


# ─────────────────────────────────────────────────────────────────────────────
# Prompt-injection (Vigil) settings
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Custom (taught) detectors
# ─────────────────────────────────────────────────────────────────────────────

def fetch_custom_manifest() -> Optional[dict]:
    """Fetch the current custom-detector manifest (signed model blobs, base64)
    from the manager server. Returns None on failure or if not configured."""
    if not ENABLED:
        return None
    try:
        r = _session.get(
            f"{SERVER_URL}/api/custom/manifest",
            headers=_headers(),
            timeout=15,
            proxies=_NO_PROXY,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[ManagerClient] fetch_custom_manifest failed: {e}")
        return None


def report_custom_question(detector_id: str, context: str, value: str, confidence: float):
    """A custom detector was unsure about a value. Report it for a human to
    answer via the Teach Astral admin page — never enforced client-side.
    Fire-and-forget, same pattern as report_dlp/report_pi."""
    if not ENABLED:
        return

    def _send():
        try:
            _session.post(
                f"{SERVER_URL}/api/custom/question",
                headers=_headers(),
                json={
                    "client_id": CLIENT_ID,
                    "detector_id": detector_id,
                    "context": context,
                    "value": value,
                    "confidence": confidence,
                },
                timeout=10,
                proxies=_NO_PROXY,
            )
        except Exception as e:
            print(f"[ManagerClient] report_custom_question failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def fetch_pi_settings() -> dict:
    """Returns {'push_enabled':bool, 'block_enabled':bool, 'warn_enabled':bool}.
    Defaults to all-enabled if server unreachable / not configured."""
    defaults = {"push_enabled": True, "block_enabled": True, "warn_enabled": True}
    if not ENABLED:
        return defaults
    try:
        r = _session.get(
            f"{SERVER_URL}/api/pi_settings",
            headers=_headers(),
            params={"client_id": CLIENT_ID},
            timeout=10,
            proxies=_NO_PROXY,
        )
        r.raise_for_status()
        data = r.json()
        return {
            "push_enabled":  bool(data.get("push_enabled", True)),
            "block_enabled": bool(data.get("block_enabled", True)),
            "warn_enabled":  bool(data.get("warn_enabled", True)),
        }
    except Exception as e:
        print(f"[ManagerClient] fetch_pi_settings failed: {e}")
        return defaults


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def report_dlp(provider: str, path: str, worst_action: str, hits: list, prompt: str = ""):
    """Send a DLP hit report to the Apexion dashboard. Fire-and-forget."""
    if not ENABLED:
        return

    def _send():
        try:
            _session.post(
                f"{SERVER_URL}/api/report/dlp",
                headers=_headers(),
                json={
                    "client_id": CLIENT_ID,
                    "provider": provider,
                    "path": path,
                    "worst_action": worst_action,
                    "hits": hits,
                    "prompt": prompt,
                },
                timeout=10,
                proxies=_NO_PROXY,
            )
        except Exception as e:
            print(f"[ManagerClient] report_dlp failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def report_pi(provider: str, path: str, action: str, score, hits: list, prompt: str = ""):
    """Send a prompt-injection hit report to the Vigil dashboard.
    Sends both warn and block level hits. Fire-and-forget."""
    if not ENABLED:
        return

    def _send():
        try:
            _session.post(
                f"{SERVER_URL}/api/report/pi",
                headers=_headers(),
                json={
                    "client_id": CLIENT_ID,
                    "provider": provider,
                    "path": path,
                    "action": action,
                    "score": score,
                    "hits": hits,
                    "prompt": prompt,
                },
                timeout=10,
                proxies=_NO_PROXY,
            )
        except Exception as e:
            print(f"[ManagerClient] report_pi failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def report_tools(tools: list, nhis: list = None):
    """Send the client's tool inventory scan and NHIs to the server. Fire-and-forget."""
    if nhis is None: nhis = []
    if not ENABLED:
        return

    def _send():
        try:
            _session.post(
                f"{SERVER_URL}/api/report/tools",
                headers=_headers(),
                json={
                    "client_id":   CLIENT_ID,
                    "client_name": CLIENT_NAME,
                    "tools":       tools,
                    "nhis":        nhis,
                },
                timeout=15,
                proxies=_NO_PROXY,
            )
            print(f"[ManagerClient] tool inventory reported ({len(tools)} tools)")
        except Exception as e:
            print(f"[ManagerClient] report_tools failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def report_catalog(entities: list):
    """Tell the server which entities this client's Presidio engine can intercept
    (auto-discovered), so the Settings page always lists the real set."""
    if not ENABLED:
        return

    def _send():
        try:
            _session.post(
                f"{SERVER_URL}/api/report/catalog",
                headers=_headers(),
                json={"client_id": CLIENT_ID, "entities": entities},
                timeout=10,
                proxies=_NO_PROXY,
            )
        except Exception as e:
            print(f"[ManagerClient] report_catalog failed: {e}")

    threading.Thread(target=_send, daemon=True).start()
