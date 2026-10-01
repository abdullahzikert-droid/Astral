# Deployment

## Server
- Python 3.10+. Install with `pip install -r server/requirements.txt`.
- For anything beyond local use, run behind a production WSGI server and HTTPS reverse proxy, for example:
  ```bash
  pip install gunicorn
  cd server && gunicorn -w 1 -b 127.0.0.1:9000 server:app
  ```
  Keep a single worker unless you move off in-process state.
- Back up `apexion_server.db` (created on first run in `server/`).
- Set `API_TOKEN`, `SECRET_KEY`, `TEACH_MODEL_KEY` to strong random values (`python -c "import secrets;print(secrets.token_hex(32))"`).

## Client
- Python 3.10+, plus the `tesseract` binary for image scanning.
- Run `python3 setup.py` (see `--help`). It is idempotent and never overwrites an existing `.env`.
- `--install-ca` trusts the mitmproxy CA system-wide and needs admin rights; otherwise install `~/.mitmproxy/mitmproxy-ca-cert.pem` yourself.
- Configure the OS or application proxy to `host:8080`.
- Fleet rollout: use `--yes` with `--server-url`, `--api-token`, `--client-id` and `--teach-key` for unattended installs.

## Upgrades
Pull the repo, re-run `python3 setup.py`, restart the client. Clients poll the server for policy changes every `CONFIG_POLL_INTERVAL` seconds.
