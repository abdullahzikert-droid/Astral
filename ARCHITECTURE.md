# Architecture

## Components

**Client (`client/`)**
- `apexion_addon.py`: mitmproxy add-on on port 8080. Inspects requests to supported AI hosts, applies the policy, and reports events.
- `presidio_engine.py`: DLP engine (Presidio, spaCy, custom and admin recognizers, deny-list, context enhancer).
- `image_scanner.py`: finds images in request bodies, runs OCR, maps hits to word boxes, and redacts pixels. Unmappable hits escalate to `block`.
- `teach_client.py` / `teach_engine.py`: load signed custom detectors pulled from the server.
- `manager_client.py`: check-in, policy and config polling, reporting.
- `tool_scanner.py`: AI tool inventory.
- `setup.py`: venv, dependencies, models, `.env`, CA certificate, self-test.

**Server (`server/`)**
- `server.py`: Flask app with session-login UI and token-authenticated client API.
- `db.py`: SQLite storage. `teach_*.py`: Teach Astral training, storage, routes. `analyzer.py`: optional Claude analysis.
- `templates/`: dashboard pages.

## Request flow
1. App sends a request through the proxy.
2. Add-on matches the host, extracts text (and images), and scans with the DLP engine plus custom detectors.
3. The worst action is applied: warn, redact, or block.
4. Hits are reported to the server.

## Client ↔ server API
Clients authenticate with the `X-Apexion-Token` header.

| Endpoint | Use |
|---|---|
| `POST /api/checkin` | Client heartbeat |
| `GET /api/config` | Policy and recognizers |
| `POST /api/report/{catalog,dlp,pi,tools}` | Event reports |
| `GET /api/custom/manifest` | Signed custom detector models |
| `POST /api/custom/question` | Teach clarification questions |

Admin endpoints live under `/api/admin/*` and `/teach/api/*` (session auth).

## Known design notes
`teach_engine.py` and `policy_defaults.py` are intentionally identical in `client/` and `server/` so each side deploys independently. Keep them in sync (see CONTRIBUTING).
