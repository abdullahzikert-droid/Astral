#!/usr/bin/env python3
"""
setup.py — one-command setup for the Apexion client (macOS / Linux / Windows).

    python3 setup.py                       # interactive
    python3 setup.py --yes --server-url http://10.0.0.5:9000 --api-token XXX --client-id laptop-1
    python3 setup.py --no-ml               # skip torch/transformers + PI model (phrase-list fallback)
    python3 setup.py --install-ca          # also trust the mitmproxy CA (needs admin/sudo)

What it does (idempotent — safe to re-run):
  1. creates ./.venv                          5. writes .env (never overwrites an existing one)
  2. installs core dependencies               6. generates the mitmproxy CA certificate
  3. downloads the spaCy model                7. optionally installs the CA into the OS trust store
  4. downloads the ML prompt-injection model  8. runs a self-test (real Presidio detection)
Standard library only, so it runs before anything is installed.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
IS_WIN = os.name == "nt"
PY = VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
DEFAULT_PI_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
CA_PEM = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

results: list[tuple[str, str, str]] = []   # (step, status, detail)


def say(msg=""):
    print(msg, flush=True)


def step(n, title):
    say(f"\n[{n}] {title}")


def record(name, status, detail=""):
    results.append((name, status, detail))
    say(f"    -> {status}{': ' + detail if detail else ''}")


def run(cmd, *, check=True, env=None, timeout=None, dry=False) -> int:
    shown = " ".join(str(c) for c in cmd)
    say(f"    $ {shown}")
    if dry:
        return 0
    try:
        p = subprocess.run([str(c) for c in cmd], cwd=HERE, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        say("    (timed out)")
        return 124
    if check and p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {shown}")
    return p.returncode


def pip(*args, dry=False):
    return run([PY, "-m", "pip", *args], dry=dry)


# ── steps ───────────────────────────────────────────────────────────────────
def check_python():
    v = sys.version_info
    if v < (3, 10):
        sys.exit(f"Python 3.10+ required (found {v.major}.{v.minor}). Install a newer Python and re-run.")
    if v >= (3, 13):
        say(f"    warning: Python {v.major}.{v.minor} — some ML wheels (torch/spaCy) may lag; 3.11/3.12 is safest.")


def make_venv(a):
    step(1, "Virtual environment")
    if PY.exists():
        return record("venv", "ok", "already exists")
    run([sys.executable, "-m", "venv", VENV], dry=a.dry_run)
    record("venv", "created", str(VENV))


def install_core(a):
    step(2, "Core dependencies (mitmproxy, Presidio, spaCy, scikit-learn ...)")
    pip("install", "--upgrade", "pip", "wheel", dry=a.dry_run)
    pip("install", "-r", "requirements.txt", dry=a.dry_run)
    record("core deps", "ok")


def check_numpy_abi(a):
    """spaCy 3.7/3.8's thinc backend breaks against numpy>=2 with a confusing
    C-extension error at import time, not install time. Catch it here."""
    if a.dry_run:
        return
    probe = ("import numpy; assert int(numpy.__version__.split('.')[0]) < 2, "
             "numpy.__version__; import thinc.backends.numpy_ops")
    p = subprocess.run([str(PY), "-c", probe], capture_output=True, text=True)
    if p.returncode != 0:
        say("    [!] numpy/thinc ABI check failed — reinstalling numpy<2 …")
        pip("install", "numpy==1.26.4", "--force-reinstall", "--no-cache-dir")
        pip("install", "-r", "requirements.txt", "--force-reinstall", "--no-cache-dir")


def check_tesseract(a):
    step("2b", "Tesseract OCR binary (image scanning)")
    if shutil.which("tesseract"):
        return record("tesseract", "ok", shutil.which("tesseract"))
    if platform.system() == "Darwin" and shutil.which("brew"):
        run(["brew", "install", "tesseract"], check=False, dry=a.dry_run)
    if shutil.which("tesseract") or a.dry_run:
        return record("tesseract", "ok")
    hint = {"Windows": "winget install UB-Mannheim.TesseractOCR  (then add it to PATH)",
            "Darwin": "brew install tesseract"}.get(platform.system(), "sudo apt-get install -y tesseract-ocr")
    record("tesseract", "MISSING", f"images will NOT be scanned until you run: {hint}")


def install_spacy_model(a):
    step(3, f"spaCy model ({a.spacy_model})")
    probe = f"import spacy; spacy.load('{a.spacy_model}')"
    if not a.dry_run and run([PY, "-c", probe], check=False) == 0:
        return record("spaCy model", "ok", "already installed")
    if run([PY, "-m", "spacy", "download", a.spacy_model], check=False, dry=a.dry_run) != 0:
        # fallback: install the wheel straight from the release page
        import re
        ver = "3.8.0"
        try:
            out = subprocess.run([str(PY), "-c", "import spacy;print(spacy.__version__)"],
                                 capture_output=True, text=True).stdout.strip()
            ver = ".".join(out.split(".")[:2]) + ".0"
        except Exception:
            pass
        url = (f"https://github.com/explosion/spacy-models/releases/download/"
               f"{a.spacy_model}-{ver}/{a.spacy_model}-{ver}-py3-none-any.whl")
        pip("install", url, dry=a.dry_run)
    record("spaCy model", "ok", a.spacy_model)


def install_ml(a):
    step(4, "ML prompt-injection guard (torch + transformers + model)")
    if a.no_ml:
        return record("ML guard", "skipped", "--no-ml (phrase-list fallback only)")
    # torch: CPU wheels on Linux/Windows avoid a ~2.5 GB CUDA download
    if not a.gpu and platform.system() in ("Linux", "Windows"):
        pip("install", "torch", "--index-url", "https://download.pytorch.org/whl/cpu", dry=a.dry_run)
    pip("install", "-r", "requirements-ml.txt", dry=a.dry_run)
    model_dir = HERE / "models" / a.pi_model.replace("/", "_")
    if model_dir.is_dir() and any(model_dir.iterdir()):
        return record("ML guard", "ok", f"model already at {model_dir.relative_to(HERE)}")
    env = dict(os.environ, APEXION_PI_MODEL=a.pi_model)
    rc = run([PY, "download_model.py"], check=False, env=env, dry=a.dry_run)
    if rc == 0:
        record("ML guard", "ok", a.pi_model)
    else:
        record("ML guard", "FAILED", "model download failed (network/HF token?) — addon will use phrase-list fallback. "
               "Retry later: python download_model.py")


def _sync_spacy_model_in_env(env_file: Path, model: str):
    """Even when .env already exists (kept, never overwritten), make sure the
    APEXION_SPACY_MODEL line matches what THIS setup run actually downloaded —
    otherwise the addon falls back to en_core_web_lg and re-downloads 400+ MB
    on first start, ignoring --spacy-model entirely."""
    text = env_file.read_text(encoding="utf-8")
    line = f"APEXION_SPACY_MODEL={model}"
    if line in text.splitlines():
        return
    import re
    if re.search(r"^APEXION_SPACY_MODEL=", text, re.M):
        text = re.sub(r"^APEXION_SPACY_MODEL=.*$", line, text, flags=re.M)
    else:
        text = text.rstrip("\n") + f"\n\n# Set by setup.py to match what it downloaded.\n{line}\n"
    env_file.write_text(text, encoding="utf-8")


def write_env(a):
    step(5, ".env configuration")
    env_file = HERE / ".env"
    if env_file.exists():
        _sync_spacy_model_in_env(env_file, a.spacy_model)
        return record(".env", "kept", "existing file not modified (spaCy model line synced)")
    example = (HERE / ".env.example").read_text(encoding="utf-8")
    vals = {"SERVER_URL": a.server_url, "API_TOKEN": a.api_token,
            "CLIENT_ID": a.client_id, "CLIENT_NAME": a.client_name, "TEACH_MODEL_KEY": a.teach_key,
            "APEXION_SPACY_MODEL": a.spacy_model}
    interactive = sys.stdin.isatty() and not a.yes
    defaults = {"SERVER_URL": "", "API_TOKEN": "", "CLIENT_ID": platform.node() or "client-1",
                "CLIENT_NAME": platform.node() or "client-1", "TEACH_MODEL_KEY": ""}
    prompts = {"SERVER_URL": "Manager server URL (blank = standalone, no dashboard)",
               "API_TOKEN": "API token (must match server)", "CLIENT_ID": "Client ID",
               "CLIENT_NAME": "Client display name", "TEACH_MODEL_KEY": "Teach model key (must match server TEACH_MODEL_KEY)"}
    for k in vals:
        if vals[k] is None:
            if interactive and (k in ("SERVER_URL", "CLIENT_ID") or vals["SERVER_URL"] or vals.get("SERVER_URL") is None):
                if k in ("API_TOKEN", "CLIENT_NAME", "TEACH_MODEL_KEY") and not vals["SERVER_URL"]:
                    vals[k] = defaults[k]
                    continue
                d = defaults[k]
                ans = input(f"    {prompts[k]}" + (f" [{d}]" if d else "") + ": ").strip()
                vals[k] = ans or d
            else:
                vals[k] = defaults[k]
    lines = []
    for line in example.splitlines():
        key = line.split("=", 1)[0].strip()
        lines.append(f"{key}={vals[key]}" if key in vals and "=" in line and not line.lstrip().startswith("#") else line)
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        env_file.chmod(0o600)
    except Exception:
        pass
    record(".env", "created", "standalone mode" if not vals["SERVER_URL"] else f"server {vals['SERVER_URL']}")


def make_ca(a):
    step(6, "mitmproxy CA certificate")
    if CA_PEM.exists():
        return record("CA cert", "ok", str(CA_PEM))
    if a.dry_run:
        return record("CA cert", "dry-run")
    mitmdump = VENV / ("Scripts/mitmdump.exe" if IS_WIN else "bin/mitmdump")
    proc = subprocess.Popen([str(mitmdump), "--listen-port", "18099", "-q"], cwd=HERE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        if CA_PEM.exists():
            break
        time.sleep(0.5)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    record("CA cert", "created" if CA_PEM.exists() else "FAILED", str(CA_PEM))


def install_ca(a):
    step(7, "Trust the CA in the OS (HTTPS interception needs this)")
    if not a.install_ca:
        return record("CA trust", "skipped", f"re-run with --install-ca, or trust {CA_PEM} manually")
    if not CA_PEM.exists():
        return record("CA trust", "FAILED", "CA file missing")
    sysname = platform.system()
    try:
        if sysname == "Darwin":
            run(["sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
                 "-k", "/Library/Keychains/System.keychain", CA_PEM], dry=a.dry_run)
        elif sysname == "Windows":
            run(["certutil", "-addstore", "-f", "ROOT", CA_PEM], dry=a.dry_run)
        elif Path("/usr/local/share/ca-certificates").exists() or shutil.which("update-ca-certificates"):
            run(["sudo", "cp", CA_PEM, "/usr/local/share/ca-certificates/apexion-mitmproxy.crt"], dry=a.dry_run)
            run(["sudo", "update-ca-certificates"], dry=a.dry_run)
        elif shutil.which("update-ca-trust"):
            run(["sudo", "cp", CA_PEM, "/etc/pki/ca-trust/source/anchors/apexion-mitmproxy.pem"], dry=a.dry_run)
            run(["sudo", "update-ca-trust", "extract"], dry=a.dry_run)
        else:
            return record("CA trust", "manual", f"unknown OS trust store — import {CA_PEM} yourself")
        record("CA trust", "ok", "Firefox uses its own store — import the cert there separately")
    except Exception as e:
        record("CA trust", "FAILED", f"{e} (needs admin/sudo)")


SELFTEST = r'''
import os, json
os.environ.setdefault("APEXION_SPACY_MODEL", "%(spacy)s")
from presidio_engine import PresidioDLPEngine
e = PresidioDLPEngine(None)
hits = e.scan("My SSN is 219-09-9999 and card 4111 1111 1111 1111, email a.b@corp.com")
ids = sorted(h["id"] for h in hits)
assert "US_SSN" in ids and "CREDIT_CARD" in ids, ids
print("SELFTEST_OK", json.dumps({"detected": ids, "entities_catalog": len(e.catalog()),
      "proof_layer": next(h for h in hits if h["id"]=="US_SSN")["proof"]["layer"]}))
'''


def selftest(a):
    step(8, "Self-test (real Presidio detection through the engine)")
    if a.dry_run:
        return record("self-test", "dry-run")
    env = dict(os.environ, APEXION_SPACY_MODEL=a.spacy_model)
    p = subprocess.run([str(PY), "-c", SELFTEST % {"spacy": a.spacy_model}], cwd=HERE, env=env,
                       capture_output=True, text=True)
    line = next((l for l in p.stdout.splitlines() if l.startswith("SELFTEST_OK")), None)
    if line:
        record("self-test", "ok", line.replace("SELFTEST_OK ", ""))
    else:
        record("self-test", "FAILED", (p.stderr or p.stdout).strip().splitlines()[-1] if (p.stderr or p.stdout).strip() else "unknown")
    if not a.no_ml:
        q = subprocess.run([str(PY), "-c", "import transformers, torch; print('ok')"], cwd=HERE,
                           capture_output=True, text=True)
        record("ML libs", "ok" if q.returncode == 0 else "FAILED", "" if q.returncode == 0 else "transformers/torch not importable")


def main():
    ap = argparse.ArgumentParser(description="Set up the Apexion client (venv, deps, models, .env, CA).")
    ap.add_argument("--spacy-model", default=os.environ.get("APEXION_SPACY_MODEL", "en_core_web_lg"),
                    help="spaCy model (default en_core_web_lg; en_core_web_sm is lighter)")
    ap.add_argument("--pi-model", default=os.environ.get("APEXION_PI_MODEL", DEFAULT_PI_MODEL))
    ap.add_argument("--no-ml", action="store_true", help="skip torch/transformers and the PI model")
    ap.add_argument("--gpu", action="store_true", help="install default torch build (CUDA) instead of CPU-only")
    ap.add_argument("--install-ca", action="store_true", help="trust the mitmproxy CA in the OS (needs admin/sudo)")
    ap.add_argument("--server-url"); ap.add_argument("--api-token")
    ap.add_argument("--client-id"); ap.add_argument("--client-name"); ap.add_argument("--teach-key")
    ap.add_argument("--yes", "-y", action="store_true", help="non-interactive; use flags/defaults")
    ap.add_argument("--dry-run", action="store_true", help="print commands without running them")
    a = ap.parse_args()
    if a.server_url is not None:
        a.server_url = a.server_url.rstrip("/")
    if a.client_id and a.client_name is None:
        a.client_name = a.client_id

    say(f"Apexion client setup — {platform.system()} {platform.machine()}, Python {platform.python_version()}")
    check_python()
    t0 = time.time()
    try:
        make_venv(a); install_core(a); check_numpy_abi(a); check_tesseract(a); install_spacy_model(a); install_ml(a)
        write_env(a); make_ca(a); install_ca(a); selftest(a)
    except (RuntimeError, KeyboardInterrupt) as e:
        say(f"\nSetup stopped: {e}")
        say("Fix the problem above and re-run — setup is idempotent.")
        sys.exit(1)

    say("\n" + "=" * 64 + "\nSUMMARY")
    for name, status, detail in results:
        say(f"  {name:<12} {status:<9} {detail}")
    failed = [r for r in results if r[1] == "FAILED"]
    say(f"\nDone in {time.time() - t0:.0f}s" + (f" with {len(failed)} problem(s)." if failed else "."))
    run_cmd = r".\start.bat" if IS_WIN else "./start.sh"
    say(f"\nStart the client:   {run_cmd}")
    say("Then point your system/browser proxy at 127.0.0.1:8080 (the addon listens on 0.0.0.0:8080).")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
