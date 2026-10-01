# Teach Astral

Teach Astral builds a custom detector from a handful of examples, with no regex writing.

## How it works
1. In the dashboard open **Teach** (`/teach`) and create a detector with a few example values (for example `ACCT-123456`).
2. Astral infers the value's *shape* and generates labelled context sentences.
3. A candidate finder (shape regex, ID-like tokens, taught words) proposes matches; a small character n-gram logistic regression judges the context.
4. The server reports held-out accuracy, then signs the model with `TEACH_MODEL_KEY`.
5. Clients pull signed models from `/api/custom/manifest`, verify the signature, and merge their hits into the normal DLP flow.

## Refining
- Add more examples, or enable/disable a detector and set its action (`warn`/`redact`/`block`).
- Uncertain matches on clients are sent as questions (`/api/custom/question`); answer them in the dashboard to improve the model.
- You can also extract examples from pasted text or an uploaded file.

## Security
`TEACH_MODEL_KEY` must match on server and clients. A client without the matching key **rejects every custom model** (fails closed). Models are pickled, so keep the key secret and never load models from untrusted servers.
