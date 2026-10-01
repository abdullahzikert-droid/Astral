"""teach_engine.py — 'Teach Astral' detection core, ported into the Apexion server.

Same design as the standalone prototype, condensed to one file:
  Shape        — infers structure from a few examples ("ACCT-" + 6 digits)
  generate()   — synthesises labelled context sentences per surface
  Detector     — candidate finder (shape regex + ID-like tokens + taught words)
                 + context judge (char n-gram logistic regression)
  probe()      — independent held-out accuracy, worded differently from generate()

A Detector produces the SAME hit shape as Apexion's regex DLPEngine
({id, label, category, severity, action}) so it can be merged into the
existing hits list with zero changes to escalate()/worst_action() logic.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import pickle
import random
import re
import string
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split

# ─────────────────────────────────────────────────────────────────────────────
# Shape inference
# ─────────────────────────────────────────────────────────────────────────────

_CLASS_CHARS = {"D": string.digits, "U": string.ascii_uppercase, "L": string.ascii_lowercase}
_CLASS_REGEX = {"D": r"\d", "U": r"[A-Z]", "L": r"[a-z]"}


def _char_class(ch: str) -> str:
    if ch.isdigit():
        return "D"
    if ch.isalpha():
        return "U" if ch.isupper() else "L"
    return ch


def _tokenize(example: str) -> list[tuple[str, str]]:
    runs: list[tuple[str, str]] = []
    for ch in example:
        cls = _char_class(ch)
        if runs and runs[-1][0] == cls and cls in _CLASS_CHARS:
            runs[-1] = (cls, runs[-1][1] + ch)
        else:
            runs.append((cls, ch))
    return runs


@dataclass(frozen=True)
class Segment:
    kind: str
    literal: str = ""
    min_len: int = 0
    max_len: int = 0

    def regex(self) -> str:
        if self.kind == "lit":
            return re.escape(self.literal)
        base = _CLASS_REGEX[self.kind]
        return f"{base}{{{self.min_len}}}" if self.min_len == self.max_len else f"{base}{{{self.min_len},{self.max_len}}}"

    def sample(self, rng: random.Random) -> str:
        if self.kind == "lit":
            return self.literal
        n = rng.randint(self.min_len, self.max_len)
        return "".join(rng.choice(_CLASS_CHARS[self.kind]) for _ in range(n))


@dataclass
class Shape:
    segments: list[Segment]

    @property
    def regex(self) -> str:
        return "".join(s.regex() for s in self.segments)

    def sample(self, rng: random.Random) -> str:
        return "".join(s.sample(rng) for s in self.segments)

    @property
    def is_specific(self) -> bool:
        has_literal = any(s.kind == "lit" and any(c.isalnum() for c in s.literal) for s in self.segments)
        return has_literal or len(self.segments) >= 3


def infer_shape(examples: list[str]) -> Shape | None:
    examples = [e.strip() for e in examples if e and e.strip()]
    if not examples:
        return None
    token_lists = [_tokenize(e) for e in examples]
    signature = [tuple(cls for cls, _ in toks) for toks in token_lists]
    if len(set(signature)) != 1:
        return None
    segments: list[Segment] = []
    for i in range(len(token_lists[0])):
        cls = token_lists[0][i][0]
        texts = [toks[i][1] for toks in token_lists]
        if cls not in _CLASS_CHARS:
            segments.append(Segment(kind="lit", literal=texts[0]))
        elif len(set(texts)) == 1 and cls in ("U", "L") and len(texts) >= 2:
            segments.append(Segment(kind="lit", literal=texts[0]))
        else:
            lens = [len(t) for t in texts]
            segments.append(Segment(kind=cls, min_len=min(lens), max_len=max(lens)))
    return Shape(segments)


def mutate_negative(shape: Shape, rng: random.Random) -> str:
    segs = list(shape.segments)
    choice = rng.choice(["anchor", "length", "separator"])
    out: list[str] = []
    for s in segs:
        if s.kind == "lit" and s.literal.strip() and any(c.isalpha() for c in s.literal) and choice == "anchor":
            out.append("".join(rng.choice(string.ascii_uppercase) for _ in s.literal))
        elif s.kind in _CLASS_CHARS and choice == "length":
            n = max(1, s.max_len + rng.choice([-3, -2, 2, 3]))
            out.append("".join(rng.choice(_CLASS_CHARS[s.kind]) for _ in range(n)))
        elif s.kind == "lit" and not any(c.isalnum() for c in s.literal) and choice == "separator":
            out.append(rng.choice([" ", "_", ""]))
        else:
            out.append(s.sample(rng))
    return "".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic context generation
# ─────────────────────────────────────────────────────────────────────────────

SURFACES = ("email", "document", "chat", "ai", "code")

_POS = {
    "email": ["Hi team, please update the record for {n} {v} before Friday.", "Subject: Issue with {n} {v}",
              "Following up on {n}: {v}. Can you confirm the status?", "Dear customer, your {n} is {v}."],
    "document": ["{n}: {v}", "Section 4. Records. The {n} on file is {v}.",
                 "Invoice reference ({n}) {v} was issued on the first of the month.", "Attached is the statement for {n} {v}."],
    "chat": ["can you look up {v}?", "ok so the {n} is {v}", "customer just gave me {v}, pulling it up now", "{v} - that's the one"],
    "ai": ["Summarise the open tickets for {n} {v}.", "Write a polite reply to the client with {n} {v} about the delayed shipment.",
           "Why is {v} showing a negative balance?", "Draft an escalation note for {v}."],
    "code": ['customer = lookup("{v}")', "# test fixture for {n} {v}", "WHERE account_id = '{v}'", '{{"id": "{v}"}}'],
}
_NEG_CONTEXT = [
    "Let's meet at {d} to review the quarterly plan.", "The order {d} shipped yesterday and should arrive on Tuesday.",
    "Reference number {d} was assigned to the maintenance ticket.", "Please review page {d} of the handbook.",
    "Build {d} passed all checks.", "My phone extension is {d}.", "How do I explain photosynthesis to a ten year old?",
    "Can you rewrite this paragraph to sound more formal?", "The meeting moved to the third floor conference room.",
    "Thanks for the update, I'll take a look this afternoon.",
]
_WORD = re.compile(r"[A-Za-z]{3,}")


def name_keywords(name: str) -> list[str]:
    return [w.lower() for w in _WORD.findall(name)]


@dataclass
class Sample:
    text: str
    label: int
    value: str | None = None


def _decoy(shape: Shape | None, rng: random.Random) -> str:
    if shape is not None and rng.random() < 0.6:
        return mutate_negative(shape, rng)
    return "".join(rng.choice("0123456789") for _ in range(rng.randint(4, 8)))


def generate(name: str, positives: list[str], surfaces: list[str], shape: Shape | None, rng: random.Random,
             n_pos: int = 240, n_neg: int = 240) -> list[Sample]:
    surfaces = [s for s in surfaces if s in _POS] or list(_POS)
    name_l = name.strip().lower()
    samples: list[Sample] = []

    def draw_value() -> str:
        if shape is not None and rng.random() < 0.7:
            return shape.sample(rng)
        return rng.choice(positives)

    for _ in range(n_pos):
        surface = rng.choice(surfaces)
        tmpl = rng.choice(_POS[surface])
        v = draw_value()
        samples.append(Sample(text=tmpl.format(v=v, n=name_l), label=1, value=v))
    for _ in range(n_neg):
        tmpl = rng.choice(_NEG_CONTEXT)
        samples.append(Sample(text=tmpl.format(d=_decoy(shape, rng)), label=0))
        if rng.random() < 0.35:
            samples.append(Sample(text=f"Where can I find my {name_l}?", label=0))
            samples.append(Sample(text=f"We are changing how we store each {name_l}.", label=0))
    rng.shuffle(samples)
    return samples


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

WINDOW = 40
MAX_SCAN_CHARS = 20_000
MAX_CANDIDATES = 500
_TOKEN_CHARS = r"A-Za-z0-9_"
# Bounded length ({0,39}): the unbounded version is O(n^2) on a long digit-free run.
FALLBACK_CANDIDATE = re.compile(r"\b(?=[A-Za-z0-9\-_/]{0,39}\d)[A-Za-z0-9][A-Za-z0-9\-_/]{3,39}\b")

ACCEPT_AT = 0.65
REJECT_AT = 0.35


def _mask(text: str, start: int, end: int) -> str:
    cand = text[start:end]
    shape_tok = re.sub(r"[A-Z]", "A", re.sub(r"[a-z]", "a", re.sub(r"\d", "9", cand)))
    left = text[max(0, start - WINDOW):start]
    right = text[end:end + WINDOW]
    return f"{left} <<{shape_tok}>> {right}"


@dataclass
class Candidate:
    start: int
    end: int
    text: str
    confidence: float

    @property
    def status(self) -> str:
        if self.confidence >= ACCEPT_AT:
            return "detected"
        if self.confidence <= REJECT_AT:
            return "ignored"
        return "uncertain"


@dataclass
class TrainReport:
    accuracy: float
    precision: float
    recall: float
    n_train: int
    n_test: int
    used_shape: bool
    warnings: list[str] = field(default_factory=list)


class Detector:
    """One taught information type. Mirrors DLPEngine's pattern shape:
    scan() returns hits with {id,label,category,severity,action} so the
    addon can merge them straight into its existing hits list."""

    def __init__(self, det_id: str, name: str, examples: list[str], surfaces: list[str],
                 action: str = "redact", severity: str = "high", seed: int = 7):
        self.id = det_id
        self.name = name
        self.examples = [e.strip() for e in examples if e.strip()]
        self.surfaces = surfaces
        self.action = action
        self.severity = severity
        self.seed = seed
        self.shape: Shape | None = infer_shape(self.examples)
        self.vectorizer: TfidfVectorizer | None = None
        self.model: LogisticRegression | None = None
        self.feedback: list[tuple[str, int]] = []
        self.report: TrainReport | None = None

    def _terms(self) -> list[str]:
        return [e for e in self.examples if not FALLBACK_CANDIDATE.fullmatch(e)]

    def _candidates(self, text: str) -> list[tuple[int, int]]:
        text = text[:MAX_SCAN_CHARS]
        found: list[tuple[int, int, int]] = []
        if self.shape is not None:
            rx = re.compile(rf"(?<![{_TOKEN_CHARS}])(?:{self.shape.regex})(?![{_TOKEN_CHARS}])")
            found += [(m.start(), m.end(), 2) for m in rx.finditer(text)]
        found += [(m.start(), m.end(), 1) for m in FALLBACK_CANDIDATE.finditer(text)]
        for term in self._terms():
            pat = rf"(?<![{_TOKEN_CHARS}]){re.escape(term)}(?![{_TOKEN_CHARS}])"
            found += [(m.start(), m.end(), 2) for m in re.finditer(pat, text, re.IGNORECASE)]
        found.sort(key=lambda t: (t[0], -(t[1] - t[0]), -t[2]))
        kept: list[tuple[int, int]] = []
        cover_end = -1
        for a, b, _ in found:
            if b <= cover_end or a < cover_end:
                continue
            kept.append((a, b))
            cover_end = b
            if len(kept) >= MAX_CANDIDATES:
                break
        return kept

    def _rows(self, samples: list[Sample]) -> tuple[list[str], list[int]]:
        X: list[str] = []
        y: list[int] = []
        for s in samples:
            if s.label == 1 and s.value is not None:
                idx = s.text.find(s.value)
                if idx >= 0:
                    X.append(_mask(s.text, idx, idx + len(s.value)))
                    y.append(1)
            else:
                spans = self._candidates(s.text)
                for a, b in spans:
                    X.append(_mask(s.text, a, b))
                    y.append(0)
                if not spans:
                    X.append(s.text)
                    y.append(0)
        return X, y

    def train(self) -> TrainReport:
        rng = random.Random(self.seed)
        warnings: list[str] = []
        if len(self.examples) < 2:
            warnings.append("Only one example given; results will be rough. Add a few more.")
        samples = generate(self.name, self.examples, self.surfaces, self.shape, rng)
        X, y = self._rows(samples)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=self.seed, stratify=y)
        Xtr = Xtr + [t for t, _ in self.feedback] * 5
        ytr = ytr + [l for _, l in self.feedback] * 5

        self.vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=1, sublinear_tf=True)
        A = self.vectorizer.fit_transform(Xtr)
        self.model = LogisticRegression(max_iter=1000, C=4.0, class_weight="balanced").fit(A, ytr)

        pred = self.model.predict(self.vectorizer.transform(Xte))
        precision = float(precision_score(yte, pred, zero_division=0))
        recall = float(recall_score(yte, pred, zero_division=0))
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)

        if self.shape is None:
            warnings.append("Your examples don't share one format, so Astral relies on surrounding wording.")
        elif not self.shape.is_specific:
            warnings.append("This looks like plain numbers; Astral will only flag it when wording nearby points to this type.")

        self.report = TrainReport(round(f1, 4), round(precision, 4), round(recall, 4), len(Xtr), len(Xte),
                                   self.shape is not None, warnings)
        return self.report

    def _shape_hit(self, cand: str) -> bool:
        return self.shape is not None and re.fullmatch(self.shape.regex, cand) is not None

    def scan(self, text: str) -> list[Candidate]:
        if self.model is None or self.vectorizer is None:
            return []
        spans = self._candidates(text)
        if not spans:
            return []
        feats = self.vectorizer.transform([_mask(text, a, b) for a, b in spans])
        probs = self.model.predict_proba(feats)[:, 1]
        out: list[Candidate] = []
        lowered_terms = {t.lower() for t in self._terms()}
        for (a, b), p in zip(spans, probs):
            cand = text[a:b]
            p = float(p)
            if self.shape is not None and not self._shape_hit(cand):
                p = min(p, 0.55) * 0.9
            if cand in self.examples:
                p = max(p, 0.99)
            elif cand.lower() in lowered_terms:
                p = min(max(p, 0.5), 0.6)
            out.append(Candidate(a, b, cand, round(p, 4)))
        return out

    def scan_hits(self, text: str) -> tuple[list[dict], list[Candidate]]:
        """Returns (enforced hits in DLPEngine's dict shape, uncertain candidates)."""
        hits, uncertain = [], []
        for c in self.scan(text):
            if c.status == "detected":
                hits.append({"id": f"CUSTOM_{self.id}", "label": self.name, "category": "custom",
                              "severity": self.severity, "action": self.action, "value": c.text,
                              "start": c.start, "end": c.end})
            elif c.status == "uncertain":
                uncertain.append(c)
        return hits, uncertain

    def learn(self, text: str, start: int, end: int, is_match: bool) -> None:
        self.feedback.append((_mask(text, start, end), 1 if is_match else 0))
        cand = text[start:end]
        if is_match and cand not in self.examples:
            self.examples.append(cand)
            self.shape = infer_shape(self.examples) or self.shape

    # ---- signed persistence (pickle + HMAC; a tampered blob is refused, never unpickled blindly) ----
    @staticmethod
    def _key() -> bytes:
        env = os.environ.get("TEACH_MODEL_KEY")
        if env:
            return env.encode()
        kp = Path(__file__).parent / "teach_model.key"
        if not kp.exists():
            kp.write_bytes(os.urandom(32))
            try:
                kp.chmod(0o600)
            except OSError:
                pass
        return kp.read_bytes()

    def dumps(self) -> bytes:
        blob = pickle.dumps(self)
        return hmac.new(self._key(), blob, hashlib.sha256).digest() + blob

    @staticmethod
    def loads(blob: bytes) -> "Detector":
        if len(blob) < 33:
            raise ValueError("model blob too short")
        mac, body = blob[:32], blob[32:]
        if not hmac.compare_digest(mac, hmac.new(Detector._key(), body, hashlib.sha256).digest()):
            raise ValueError("model signature mismatch; refusing to load")
        return pickle.loads(body)  # noqa: S301 - signature verified above


# ─────────────────────────────────────────────────────────────────────────────
# Independent self-test (worded differently from generate(), so it isn't graded on its own homework)
# ─────────────────────────────────────────────────────────────────────────────

_POS_PROBES = [
    "fwd from ops -- {v} needs a refund, customer is angry", "(ref {v}) escalated to tier 2",
    "he read out {v} over the phone and then hung up", "| {v} | active | 2024-03-01 |",
    "re: {v} // sorry for the delay!!", "Handling {v}, plus two others from last week.",
    "ticket body: the client with {v} cannot log in since monday", "see also {v}.",
]
_NEG_PROBES = [
    "order {d} left the warehouse this morning", "call me on {d} when you land",
    "release tag {d} is live in staging", "The quarterly numbers look fine to me.",
    "Could you resend the deck from yesterday's sync?", "lunch at noon? the usual place",
    "Page {d} has a typo in the second paragraph.", "ETA is {d} minutes, traffic is bad",
]


@dataclass
class ProbeResult:
    accuracy: float
    precision: float
    recall: float


def probe(det: Detector, seed: int = 99, n_each: int = 50) -> ProbeResult:
    rng = random.Random(seed)
    tp = fp = fn = 0
    for _ in range(n_each):
        value = det.shape.sample(rng) if det.shape is not None and rng.random() < 0.8 else rng.choice(det.examples)
        text = rng.choice(_POS_PROBES).format(v=value)
        hit = any(c.status == "detected" and c.text == value for c in det.scan(text))
        tp += hit
        fn += not hit
    for _ in range(n_each):
        tmpl = rng.choice(_NEG_PROBES)
        text = tmpl.format(d=mutate_negative(det.shape, rng) if det.shape is not None and rng.random() < 0.6
                            else str(rng.randint(1000, 999999))) if "{d}" in tmpl else tmpl
        fired = any(c.status == "detected" for c in det.scan(text))
        fp += fired
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return ProbeResult(round(f1, 4), round(precision, 4), round(recall, 4))
