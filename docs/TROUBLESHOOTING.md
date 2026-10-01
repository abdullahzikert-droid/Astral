# Troubleshooting

| Symptom | Fix |
|---|---|
| Browser/app shows TLS errors | Install and trust the mitmproxy CA (`setup.py --install-ca`) |
| Client says unauthorized | `API_TOKEN` differs between client and server |
| Custom detectors never load | `TEACH_MODEL_KEY` mismatch (clients fail closed) |
| Image scanning disabled | Install the `tesseract` binary; check `APEXION_IMAGE_SCAN=1` |
| Unscannable images get through | Set `APEXION_IMAGE_FAIL_MODE=closed` |
| ML injection guard missing | Install `requirements-ml.txt` or rerun `setup.py` without `--no-ml`; phrase list is used otherwise |
| spaCy model errors | `python download_model.py` or `python -m spacy download en_core_web_lg` |
| Need to see what is sent | Run with `APEXION_CAPTURE=1` for a clean trace (avoid `APEXION_DEBUG_POSTS`) |
| AI recommendations empty | Set `ANTHROPIC_API_KEY` on the server |
