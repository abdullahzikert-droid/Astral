"""Default Presidio detection policy + merge helper.

IDENTICAL copy lives in client/ and server/server/ — edit both together.
The manager server stores only OVERRIDES of these defaults (edited through the
Settings form, not raw JSON); clients merge them over these defaults at startup.

action: warn | redact | block | ignore
"""
from __future__ import annotations

import copy

ACTIONS = ("warn", "redact", "block", "ignore")
SEVERITIES = ("low", "medium", "high", "critical")


def _e(label, category, severity, action):
    return {"label": label, "category": category, "severity": severity, "action": action}


DEFAULT_POLICY = {
    "score_threshold": 0.5,
    "deny_list": [],                       # org-specific terms -> Presidio deny-list recognizer
    "entities": {
        # ── personal identifiers ────────────────────────────────────────────
        "US_SSN":            _e("US Social Security Number", "pii", "critical", "block"),
        "US_ITIN":           _e("US Taxpayer ID (ITIN)", "pii", "critical", "block"),
        "US_PASSPORT":       _e("US Passport Number", "pii", "critical", "block"),
        "US_DRIVER_LICENSE": _e("US Driver License", "pii", "high", "redact"),
        "UK_NINO":           _e("UK National Insurance Number", "pii", "critical", "block"),
        "UK_NHS":            _e("UK NHS Number", "pii", "critical", "block"),
        "SG_NRIC_FIN":       _e("Singapore NRIC/FIN", "pii", "critical", "block"),
        "AU_TFN":            _e("Australian Tax File Number", "pii", "critical", "block"),
        "AU_MEDICARE":       _e("Australian Medicare Number", "pii", "critical", "block"),
        "AU_ABN":            _e("Australian Business Number", "pii", "low", "warn"),
        "AU_ACN":            _e("Australian Company Number", "pii", "low", "warn"),
        "IN_AADHAAR":        _e("India Aadhaar Number", "pii", "critical", "block"),
        "IN_PAN":            _e("India PAN", "pii", "critical", "block"),
        "IN_PASSPORT":       _e("India Passport Number", "pii", "critical", "block"),
        "IN_VOTER":          _e("India Voter ID", "pii", "high", "block"),
        "IN_VEHICLE_REGISTRATION": _e("India Vehicle Registration", "pii", "medium", "redact"),
        "PK_CNIC":           _e("Pakistan CNIC", "pii", "critical", "block"),
        "MEDICAL_LICENSE":   _e("Medical License", "pii", "medium", "redact"),
        "PHI_MRN":           _e("Medical Record Number", "pii", "high", "block"),
        "PERSON":            _e("Person Name", "pii", "low", "warn"),
        "EMAIL_ADDRESS":     _e("Email Address", "pii", "medium", "redact"),
        "PHONE_NUMBER":      _e("Phone Number", "pii", "medium", "redact"),
        "LOCATION":          _e("Location", "pii", "low", "warn"),
        "NRP":               _e("Nationality / Religion / Political group", "pii", "low", "ignore"),
        "DATE_TIME":         _e("Date / Time", "pii", "low", "ignore"),
        "URL":               _e("URL", "network", "low", "ignore"),
        # ── financial ───────────────────────────────────────────────────────
        "CREDIT_CARD":       _e("Credit Card Number", "financial", "critical", "block"),
        "IBAN_CODE":         _e("IBAN", "financial", "critical", "block"),
        "US_BANK_NUMBER":    _e("Bank Account Number", "financial", "critical", "block"),
        "CRYPTO":            _e("Crypto Wallet", "financial", "high", "block"),
        # ── secrets ─────────────────────────────────────────────────────────
        "API_KEY":           _e("API Key / Token", "secrets", "critical", "block"),
        "JWT":               _e("JWT", "secrets", "critical", "block"),
        "PRIVATE_KEY":       _e("Private Key Block", "secrets", "critical", "block"),
        "HIGH_ENTROPY_SECRET": _e("High-entropy Secret", "secrets", "high", "redact"),
        # ── network / org ───────────────────────────────────────────────────
        "IP_ADDRESS":        _e("IP Address", "network", "medium", "redact"),
        "ORG_DENY_TERM":     _e("Organisation deny-list term", "custom", "high", "redact"),
    },
    "fallback": {"category": "pii", "severity": "low", "action": "warn"},
}


_FIN = ("CREDIT_CARD", "DEBIT_CARD", "IBAN", "BANK", "CRYPTO", "ROUTING", "SWIFT", "ACCOUNT")
_SEC = ("KEY", "TOKEN", "SECRET", "JWT", "PASSWORD", "CREDENTIAL")
_NET = ("IP_", "URL", "DOMAIN", "MAC_")


def auto_meta(entity: str, layer: str = "") -> dict:
    """Sensible metadata for an entity Presidio reports that we have no curated
    entry for (auto-discovered). NER entities warn; structured identifiers redact;
    secrets block."""
    up = entity.upper()
    _acr = {"ES", "IT", "PL", "FI", "SG", "UK", "US", "AU", "IN", "PK", "NIF", "NIE", "UEN", "VAT", "PESEL",
            "ABA", "NHS", "NINO", "TFN", "ABN", "ACN", "PAN", "MRN", "CNIC", "IP", "JWT", "API", "URL", "ID"}
    label = " ".join(w if w in _acr else w.title() for w in entity.upper().split("_"))
    if any(k in up for k in _SEC):
        return _e(label, "secrets", "critical", "block")
    if any(k in up for k in _FIN):
        return _e(label, "financial", "high", "redact")
    if any(k in up for k in _NET):
        return _e(label, "network", "medium", "warn")
    if "NER" in layer:
        return _e(label, "pii", "low", "warn")
    return _e(label, "pii", "medium", "redact")


def merge_policy(stored: dict | None) -> dict:
    """defaults <- stored overrides. Tolerates the legacy shape that had a
    top-level `default` and `ignored_entities`."""
    pol = copy.deepcopy(DEFAULT_POLICY)
    stored = stored or {}
    if isinstance(stored.get("score_threshold"), (int, float)):
        pol["score_threshold"] = float(stored["score_threshold"])
    if isinstance(stored.get("deny_list"), list):
        pol["deny_list"] = [str(t).strip() for t in stored["deny_list"] if str(t).strip()]
    for name, ov in (stored.get("entities") or {}).items():
        if not isinstance(ov, dict):
            continue
        cur = pol["entities"].setdefault(name, auto_meta(name))
        for k in ("label", "category", "severity", "action"):
            if ov.get(k):
                cur[k] = ov[k]
    for name in stored.get("ignored_entities") or []:
        if name in pol["entities"]:
            pol["entities"][name]["action"] = "ignore"
    if stored.get("default"):
        pol["fallback"].update(stored["default"])
    return pol


# Which Presidio layer normally produces each entity (shown in Settings).
ENTITY_LAYER = {
    "PERSON": "NER (spaCy)", "LOCATION": "NER (spaCy)", "NRP": "NER (spaCy)",
    "PHONE_NUMBER": "Library (phonenumbers) + context",
    "API_KEY": "Custom pattern", "JWT": "Custom pattern", "PRIVATE_KEY": "Custom pattern",
    "PHI_MRN": "Custom pattern", "PK_CNIC": "Custom pattern",
    "HIGH_ENTROPY_SECRET": "Custom entropy",
    "ORG_DENY_TERM": "Deny-list",
}
DEFAULT_LAYER = "Predefined pattern + checksum + context"


def overrides_from(policy: dict) -> dict:
    """Reduce a full policy to only what differs from DEFAULT_POLICY (what the server stores)."""
    out = {"score_threshold": policy["score_threshold"], "deny_list": policy.get("deny_list", []), "entities": {}}
    for name, cur in policy["entities"].items():
        base = DEFAULT_POLICY["entities"].get(name, {})
        diff = {k: v for k, v in cur.items() if base.get(k) != v}
        if diff:
            out["entities"][name] = diff
    return out
