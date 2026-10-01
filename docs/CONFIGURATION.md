# Configuration

## Server (`server/.env`)
| Variable | Description |
|---|---|
| `API_TOKEN` | Shared secret clients send in `X-Apexion-Token` |
| `SECRET_KEY` | Flask session signing key (long random string) |
| `HOST`, `PORT` | Bind address and port (default port 9000) |
| `TEACH_MODEL_KEY` | Key used to sign Teach models; must match clients |
| `ANTHROPIC_API_KEY` | Optional, enables AI isolation recommendations |

## Client (`client/.env`, written by `setup.py`)
| Variable | Description |
|---|---|
| `SERVER_URL` | Manager URL; empty means standalone |
| `API_TOKEN`, `CLIENT_ID`, `CLIENT_NAME` | Auth and identity |
| `TEACH_MODEL_KEY` | Must match the server, otherwise custom models are rejected |
| `CONFIG_POLL_INTERVAL`, `CONFIG_RETRY_BACKOFF` | Polling seconds |
| `APEXION_SPACY_MODEL` | spaCy model (default `en_core_web_lg`) |
| `APEXION_IMAGE_SCAN` | `1`/`0`, requires the `tesseract` binary |
| `APEXION_IMAGE_FAIL_MODE` | `open` or `closed` for unscannable images |
| `APEXION_IMAGE_NOTIFY`, `APEXION_IMAGE_DEBUG`, `APEXION_DEBUG_POSTS`, `APEXION_CAPTURE` | Debug and notification toggles |

Image tuning: `APEXION_IMAGE_MAX_BYTES`, `APEXION_IMAGE_MAX_COUNT`, `APEXION_OCR_MIN_CONF`, `APEXION_OCR_PSM`, `APEXION_OCR_LANG`, `APEXION_OCR_TIMEOUT`.

Prompt-injection phrases: edit `client/jailbreak_phrases.txt` (one lowercase phrase per line).
