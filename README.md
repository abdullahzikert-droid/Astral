# 🌌 Astral

**A DLP firewall for AI usage.** Astral intercepts traffic from your machines to AI providers, detects sensitive data and prompt injection, and blocks, redacts, or warns, all managed from a central dashboard.

```
 Laptop / IDE ──► Astral client (mitmproxy) ──► Claude · ChatGPT · Gemini · APIs
                        │  policy, detections, reports
                        ▼
                 Astral server (Flask dashboard)
```

## Features

- **Inline DLP** with Microsoft Presidio and spaCy: PII, secrets, and custom recognizers.
- **Per-hit actions:** `warn` (header injected), `redact` (`[REDACTED:<id>]`), or `block` (403). The worst action wins.
- **Covered providers:** Anthropic (API and claude.ai), OpenAI (API and ChatGPT/Codex), Google Gemini API.
- **Image scanning:** OCR (Tesseract) feeds the same DLP engine, with pixel-level black-box redaction.
- **Prompt-injection guard:** optional ML model, with a phrase-list fallback.
- **Teach Astral:** give a few examples of your own identifiers and Astral trains a custom detector. Models are signed by the server and verified by clients (fails closed).
- **AI tool inventory:** detects installed AI apps, CLIs, and IDE extensions (macOS), with optional Claude-powered isolation recommendations.
- **Central management:** policy, recognizers, audit log, and dashboards (Overview, Apexion, Vigil, Teach, Settings).

## Repository layout

| Path | Purpose |
|---|---|
| `client/` | mitmproxy add-on, DLP engine, image scanner, tool scanner, setup |
| `server/` | Flask manager: API, dashboard, Teach routes, SQLite store |
| `docs/` | Policy, Teach, configuration, deployment, troubleshooting |

## Quick start

**1. Server**
```bash
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # set API_TOKEN and SECRET_KEY
python server.py         # http://localhost:9000
```
Open the dashboard and create the first user at `/login`.

**2. Client** (macOS / Linux / Windows)
```bash
cd client
python3 setup.py --server-url http://localhost:9000 --api-token <API_TOKEN> --install-ca
./start.sh               # start.bat on Windows
```
Then point your system or app proxy at `localhost:8080`. `setup.py --no-ml` skips the heavy ML model.
Leave `SERVER_URL` empty to run standalone with a local policy cache.

## Documentation

- [Architecture](ARCHITECTURE.md)
- [Policy guide](docs/POLICY.md)
- [Teach Astral](docs/TEACH.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Configuration](docs/CONFIGURATION.md)
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Status

Early-stage. Review the [security notes](SECURITY.md) before deploying beyond a trusted network.

## License

[MIT](LICENSE)
