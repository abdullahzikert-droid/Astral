"""teach_extract.py — 'Show Astral examples': mine a sample document for candidate values."""
from __future__ import annotations

from collections import defaultdict

from teach_engine import FALLBACK_CANDIDATE, _tokenize, name_keywords

MAX_TEXT = 2_000_000


def _signature(tok: str) -> tuple:
    runs = _tokenize(tok)
    sig = []
    for cls, text in runs:
        if cls in ("D", "U", "L"):
            sig.append((cls, text if (cls in ("U", "L") and len(text) <= 5) else len(text)))
        else:
            sig.append((cls, text))
    return tuple(sig)


def find_examples(text: str, name: str, limit: int = 60) -> dict:
    text = text[:MAX_TEXT]
    tokens = [m.group() for m in FALLBACK_CANDIDATE.finditer(text)]
    groups: dict[tuple, list[str]] = defaultdict(list)
    for t in tokens:
        groups[_signature(t)].append(t)

    kws = name_keywords(name)

    def score(item: tuple) -> float:
        sig, vals = item
        uniq = len(set(vals))
        prefix = "".join(str(p[1]) for p in sig if p[0] in ("U", "L") and isinstance(p[1], str)).lower()
        name_bonus = 3.0 if prefix and any(prefix[:3] == k[:3] or k.startswith(prefix) for k in kws) else 1.0
        structure = 2.0 if any(p[0] == "-" or (p[0] in ("U", "L") and isinstance(p[1], str)) for p in sig) else 1.0
        return uniq * name_bonus * structure

    ranked = sorted(groups.items(), key=score, reverse=True)
    clusters = []
    for sig, vals in ranked[:5]:
        uniq = list(dict.fromkeys(vals))
        clusters.append({"count": len(uniq), "examples": uniq[:limit]})

    best = clusters[0] if clusters else {"count": 0, "examples": []}
    return {"best": best, "other_clusters": clusters[1:], "tokens_scanned": len(tokens)}
