#!/usr/bin/env bash
# Start the Apexion client proxy (macOS / Linux)
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || { echo "Run: python3 setup.py   first"; exit 1; }
exec .venv/bin/python apexion_addon.py
