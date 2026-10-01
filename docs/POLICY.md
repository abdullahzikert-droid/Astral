# Policy guide

Defaults live in `policy_defaults.py` (identical in `client/` and `server/`). The server stores only your **overrides**, edited in the dashboard under **Settings**. Clients merge overrides over the defaults.

## Actions
| Action | Effect |
|---|---|
| `ignore` | Entity is not reported |
| `warn` | Request passes; `X-Apexion-Warning` header is added to the response |
| `redact` | Match is replaced with `[REDACTED:<id>]` and the cleaned request is forwarded |
| `block` | Request gets HTTP 403 and never reaches the provider |

When a request has several hits, the **worst** action wins (`ignore < warn < redact < block`).

## Policy fields
- `score_threshold` (default `0.5`): minimum Presidio confidence for a hit.
- `deny_list`: organisation-specific terms, always flagged.
- `entities`: per entity type, a `label`, `category`, `severity` (`low`/`medium`/`high`/`critical`) and `action`. Defaults cover US, UK, India, Singapore and Australia identifiers, among others.

## Custom recognizers
Admins can add regex recognizers in the dashboard (`/api/admin/recognizers`), test them before saving, and toggle or delete them. For identifiers without a clean pattern, use [Teach Astral](TEACH.md).

## Prompt injection
Scored by an optional ML model; without it, Astral falls back to the substring list in `client/jailbreak_phrases.txt`.
