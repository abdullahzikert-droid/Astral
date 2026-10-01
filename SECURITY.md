# Security

## Reporting a vulnerability
Please report privately through GitHub Security Advisories (Security tab → Report a vulnerability). Do not open public issues for vulnerabilities.

## Deployment notes
- Change the default `API_TOKEN` (`change-me-token`) and set a random `SECRET_KEY` and `TEACH_MODEL_KEY`.
- Serve the manager behind HTTPS; the token and sessions are otherwise sent in clear text.
- The client proxy binds to `0.0.0.0:8080`. Restrict it with a firewall if it should not be reachable from other hosts.
- The mitmproxy CA you install can decrypt TLS on that machine. Protect `~/.mitmproxy` and only trust it on managed devices.
- Never commit `.env` files or `*.db`; both are in `.gitignore`.
- OCR debug mode prints screenshot text to the console. Keep `APEXION_IMAGE_DEBUG=0` in production.
