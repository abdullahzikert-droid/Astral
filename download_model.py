"""
download_model.py — one-time setup for Apexion's ML prompt-injection guard

Run this ONCE, on a machine with internet access, in the same directory as
apexion_addon.py:

    pip install transformers torch
    python3 download_model.py

Downloads whatever APEXION_PI_MODEL points to (same env var apexion_addon.py
reads) and saves it into ./models/<model-name>/. Default, if unset:

    protectai/deberta-v3-base-prompt-injection-v2      (ungated, no token needed)

Other tested options:

    APEXION_PI_MODEL=meta-llama/Llama-Prompt-Guard-2-86M   (GATED — see below)
    APEXION_PI_MODEL=meta-llama/Llama-Prompt-Guard-2-22M   (GATED, smaller/faster)

Gated models (anything under meta-llama/) require you to:
  1. Log into huggingface.co with your account and accept the license on the
     model's page (e.g. https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M).
  2. Create an access token at https://huggingface.co/settings/tokens.
  3. Set it here: export APEXION_HF_TOKEN=hf_xxxxx  (or the standard HF_TOKEN).
Without both steps, the download fails with a 401/403 — that's the license
gate, not a bug.

apexion_addon.py auto-detects the per-model folder under models/ and loads it
fully offline (local_files_only=True) on every future run — no network call
at request time, no re-download on restart.

To switch models later, just set APEXION_PI_MODEL to something new and re-run
this script — it downloads into a NEW folder rather than overwriting the old
one, so you can switch back by just changing the env var again. To force a
re-download of the SAME model, delete its models/<name>/ folder first.

After any model swap, watch the first line the addon prints on startup:
    [Apexion] prompt-injection guard labels for <model>: safe=[...] unsafe=[...]
If safe=[] , the model's labels weren't recognized automatically — set
APEXION_PI_SAFE_LABELS (see apexion_addon.py's PromptInjectionGuard docstring)
before relying on it.
"""

import os
from pathlib import Path

MODEL     = os.environ.get("APEXION_PI_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
HF_TOKEN  = os.environ.get("APEXION_HF_TOKEN") or os.environ.get("HF_TOKEN")
MODEL_DIR = Path(__file__).parent / "models" / MODEL.replace("/", "_")


def main():
    if MODEL_DIR.is_dir() and any(MODEL_DIR.iterdir()):
        print(f"[*] {MODEL_DIR} already populated — nothing to do.")
        print("    Delete it first if you want to re-download.")
        return

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        print("    Install with: pip install transformers torch")
        return

    auth = {"token": HF_TOKEN} if HF_TOKEN else {}
    if "meta-llama" in MODEL and not HF_TOKEN:
        print(f"[!] {MODEL} is a gated model. You need to:")
        print(f"    1. Accept its license at https://huggingface.co/{MODEL}")
        print("    2. Create a token at https://huggingface.co/settings/tokens")
        print("    3. export APEXION_HF_TOKEN=hf_xxxxx")
        print("    Attempting anyway — this will fail without the above.")

    print(f"[*] Downloading {MODEL} …")
    tokenizer = AutoTokenizer.from_pretrained(MODEL, **auth)
    model     = AutoModelForSequenceClassification.from_pretrained(MODEL, **auth)

    id2label = getattr(model.config, "id2label", {})
    print(f"[*] Model's labels: {dict(id2label)}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Saving to {MODEL_DIR} …")
    tokenizer.save_pretrained(MODEL_DIR)
    model.save_pretrained(MODEL_DIR)

    size_mb = sum(f.stat().st_size for f in MODEL_DIR.rglob("*") if f.is_file()) / (1024 * 1024)
    print(f"[+] Done. {MODEL_DIR} ({size_mb:.1f} MB)")
    print("[+] apexion_addon.py will now load this model fully offline (same APEXION_PI_MODEL value).")


if __name__ == "__main__":
    main()
