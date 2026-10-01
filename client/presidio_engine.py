"""presidio_engine.py — Presidio-backed DLP engine with per-hit PROOF.

Presidio components wired in:
  * AnalyzerEngine + spaCy NLP engine            -> NER layer (SpacyRecognizer)
  * all predefined recognizers for 'en'          -> pattern / checksum / library layers
  * custom PatternRecognizers                    -> API keys, JWT, PEM, MRN, CNIC
  * entropy recognizer (validate_result)         -> statistical layer
  * deny-list recognizer (policy.deny_list)      -> org-term layer
  * LemmaContextAwareEnhancer                    -> context-word score boost
  * AnonymizerEngine (replace operator)          -> redaction
Every analyze() runs with return_decision_process=True, so each hit carries a
`proof` dict: which layer/recognizer/pattern fired, original vs final score,
checksum validation, context boost, span and a masked preview.
Non-Presidio layers (phrase heuristic, ML classifier, Teach Astral) attach the
same proof shape with proof["engine"] telling which system produced it.
"""
from __future__ import annotations

import json
import math
import os
import threading
from pathlib import Path
from typing import Optional

try:                       # so APEXION_SPACY_MODEL from .env is honored even
    from dotenv import load_dotenv   # if this module is imported before
    load_dotenv()                    # manager_client (which also calls this)
except ImportError:
    pass

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
from presidio_anonymizer.entities import RecognizerResult as AnonResult

from policy_defaults import merge_policy, auto_meta

SPACY_MODEL = os.environ.get("APEXION_SPACY_MODEL", "en_core_web_lg")
ACTION_RANK = {"ignore": -1, "warn": 0, "redact": 1, "block": 2}
PROMPT_INJECTION_ESCALATION_THRESHOLD = 2
PHRASES_FILE = Path(__file__).parent / "jailbreak_phrases.txt"
DENY_RECOGNIZER_NAME = "OrgDenyListRecognizer"


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def preview(text: str, start: int, end: int) -> str:
    """Masked view of the matched value (proof without re-leaking it)."""
    v = text[start:end]
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * min(len(v) - 4, 12) + v[-2:]


class _HighEntropyRecognizer(PatternRecognizer):
    def __init__(self):
        from presidio_analyzer import Pattern as P
        super().__init__(
            supported_entity="HIGH_ENTROPY_SECRET", name="HighEntropySecretRecognizer",
            patterns=[P("high_entropy_candidate", r"\b[A-Za-z0-9_\-/+=]{24,}\b", 0.3)],
            context=["secret", "key", "token", "credential", "password"])

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        return _entropy(pattern_text) >= 4.0


# name -> human layer label for recognizers WE add
_CUSTOM_LAYERS = {
    "AWSAccessKey": "Custom pattern recognizer",
    "GenericApiKey": "Custom pattern recognizer",
    "JWT": "Custom pattern recognizer",
    "PrivateKeyBlock": "Custom pattern recognizer",
    "MRN": "Custom pattern recognizer",
    "PakistanCNIC": "Custom pattern recognizer",
    "HighEntropySecretRecognizer": "Custom statistical (entropy) recognizer",
    DENY_RECOGNIZER_NAME: "Deny-list recognizer",
}


def _custom_recognizers() -> list[PatternRecognizer]:
    return [
        PatternRecognizer("API_KEY", name="AWSAccessKey",
                          patterns=[Pattern("aws", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.9)],
                          context=["aws", "access", "key", "iam"]),
        PatternRecognizer("API_KEY", name="GenericApiKey",
                          patterns=[
                              Pattern("kv", r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", 0.75),
                              Pattern("sk", r"\bsk-[A-Za-z0-9_\-]{20,}\b", 0.85),
                              Pattern("github", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0.9),
                              Pattern("slack", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", 0.9),
                              Pattern("google", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.9),
                          ],
                          context=["api", "key", "secret", "token", "credential"]),
        PatternRecognizer("JWT", name="JWT",
                          patterns=[Pattern("jwt", r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0.9)],
                          context=["jwt", "bearer", "token", "authorization"]),
        PatternRecognizer("PRIVATE_KEY", name="PrivateKeyBlock",
                          patterns=[Pattern("pem", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----", 0.95)]),
        PatternRecognizer("PHI_MRN", name="MRN",
                          patterns=[Pattern("mrn", r"(?i)\bMRN[:\s#]*\d{4,10}\b", 0.85)],
                          context=["mrn", "medical", "record", "patient"]),
        PatternRecognizer("PK_CNIC", name="PakistanCNIC",
                          patterns=[Pattern("cnic_dashed", r"\b\d{5}-\d{7}-\d\b", 0.85),
                                    Pattern("cnic_plain", r"\b\d{13}\b", 0.2)],
                          context=["cnic", "nic", "identity", "national id"]),
        _HighEntropyRecognizer(),
    ]


class PresidioDLPEngine:
    def __init__(self, policy_cache: Optional[Path] = None):
        self._cache = policy_cache
        self.policy: dict = {}
        self._phrases: list[str] = []
        self._analyzer: Optional[AnalyzerEngine] = None
        self._anonymizer = AnonymizerEngine()
        self._layer_of: dict[str, str] = {}
        self._lock = threading.RLock()     # scans now run on worker threads
        self.load()

    # ── setup ────────────────────────────────────────────────────────────────
    def load(self):
        stored = None
        if self._cache and self._cache.exists():
            try:
                stored = json.loads(self._cache.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[DLP] policy cache unreadable ({e}); using built-in defaults")
        self.policy = merge_policy(stored)
        self._admin_recognizers = (stored or {}).get("custom_recognizers", [])
        # admin-defined recognizers carry their own label/category/severity/action —
        # fold that into policy['entities'] so _meta()/auto_meta never overrides it
        for r in self._admin_recognizers:
            if r.get("enabled", True):
                self.policy["entities"][r["entity"]] = {
                    "label": r["label"], "category": r["category"],
                    "severity": r["severity"], "action": r["action"],
                }

        try:
            lines = PHRASES_FILE.read_text(encoding="utf-8").splitlines()
            self._phrases = [l.strip().lower() for l in lines if l.strip() and not l.startswith("#")]
        except Exception:
            self._phrases = []

        if self._analyzer is None:
            nlp = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
            }).create_engine()
            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp, supported_languages=["en"],
                context_aware_enhancer=LemmaContextAwareEnhancer())   # explicit: context layer
            for r in _custom_recognizers():
                self._analyzer.registry.add_recognizer(r)
            self._auto_load_recognizers()
        self._index_layers()
        self._apply_admin_recognizers()   # rebuilt every load() — admin can add/edit/remove live
        self._apply_deny_list()
        self._log_layers()

    def _auto_load_recognizers(self):
        """Discover EVERY pattern/checksum recognizer this Presidio install ships
        (incl. ones only registered for other languages: ES_NIF, IT_FISCAL_CODE,
        PL_PESEL, ABA routing...) and register them for English text. New Presidio
        versions are picked up automatically. Model-based recognizers (Stanza,
        Transformers, GLiNER, Azure) are skipped — spaCy NER already covers that layer."""
        import inspect
        import presidio_analyzer.predefined_recognizers as pr
        loaded = {type(r).__name__ for r in self._analyzer.registry.recognizers}
        added = []
        for name in sorted(getattr(pr, "__all__", [])):
            cls = getattr(pr, name, None)
            if name in loaded or not inspect.isclass(cls) or not issubclass(cls, PatternRecognizer):
                continue
            try:
                self._analyzer.registry.add_recognizer(cls(supported_language="en"))
                added.append(name)
            except Exception:
                pass
        if added:
            print(f"[DLP] auto-discovered extra Presidio recognizers: {', '.join(added)}")

    def _ner_entities(self) -> set:
        """Entities the spaCy model can ACTUALLY emit (model labels -> Presidio entities,
        minus ignored labels), not everything SpacyRecognizer nominally lists."""
        try:
            cfg = self._analyzer.nlp_engine.ner_model_configuration
            labels = set(self._analyzer.nlp_engine.nlp["en"].get_pipe("ner").labels)
            return {cfg.model_to_presidio_entity_mapping[l] for l in labels
                    if l in cfg.model_to_presidio_entity_mapping and l not in cfg.labels_to_ignore}
        except Exception:
            return {"PERSON", "LOCATION", "NRP", "DATE_TIME"}

    def catalog(self) -> list[dict]:
        """Everything this engine can intercept: [{entity, recognizers, layers}]."""
        ner = self._ner_entities()
        cat: dict[str, dict] = {}
        for r in self._analyzer.registry.recognizers:
            layer = self._layer_of.get(r.name, "Presidio recognizer")
            ents = [e for e in r.supported_entities if e in ner] if layer == "NER (spaCy)" else r.supported_entities
            for e in ents:
                c = cat.setdefault(e, {"entity": e, "recognizers": [], "layers": []})
                if r.name not in c["recognizers"]:
                    c["recognizers"].append(r.name)
                if layer not in c["layers"]:
                    c["layers"].append(layer)
        return sorted(cat.values(), key=lambda c: c["entity"])

    def _apply_admin_recognizers(self):
        """Server-admin-defined recognizers (regex or deny-list, built in the
        Settings UI — no code). Removed and re-added on every policy refresh
        so edits/deletes take effect on the next config poll, no client restart."""
        reg = self._analyzer.registry
        for name in list(self._layer_of):
            if name.startswith("Admin:"):
                try:
                    reg.remove_recognizer(name)
                except Exception:
                    pass
        for r in getattr(self, "_admin_recognizers", []):
            if not r.get("enabled", True):
                continue
            rname = f"Admin:{r['id']}"
            try:
                if r["kind"] == "regex":
                    pr = PatternRecognizer(
                        r["entity"], name=rname,
                        patterns=[Pattern(r["id"], r["pattern"]["regex"], float(r["pattern"].get("score", 0.75)))],
                        context=r.get("context") or [])
                elif r["kind"] == "deny_list":
                    pr = PatternRecognizer(
                        supported_entity=r["entity"], name=rname,
                        deny_list=r["pattern"].get("terms", []),
                        deny_list_score=float(r["pattern"].get("score", 0.9)))
                else:
                    continue
                reg.add_recognizer(pr)
                self._layer_of[rname] = f"Admin recognizer ({r['name']})"
            except Exception as e:
                print(f"[DLP] admin recognizer '{r.get('name', r.get('id'))}' failed to load: {e}")

    def _apply_deny_list(self):
        reg = self._analyzer.registry
        try:
            reg.remove_recognizer(DENY_RECOGNIZER_NAME)
        except Exception:
            pass
        terms = self.policy.get("deny_list") or []
        if terms:
            reg.add_recognizer(PatternRecognizer(
                supported_entity="ORG_DENY_TERM", name=DENY_RECOGNIZER_NAME,
                deny_list=terms, deny_list_score=0.95))

    def _index_layers(self):
        self._layer_of = {}
        for r in self._analyzer.registry.recognizers:
            if r.name in _CUSTOM_LAYERS:
                layer = _CUSTOM_LAYERS[r.name]
            elif type(r).__name__ == "SpacyRecognizer":
                layer = "NER (spaCy)"
            elif isinstance(r, PatternRecognizer):
                layer = "Predefined pattern recognizer"
            else:
                layer = "Predefined library recognizer"
            self._layer_of[r.name] = layer

    def _log_layers(self):
        counts: dict[str, int] = {}
        for l in self._layer_of.values():
            counts[l] = counts.get(l, 0) + 1
        print("[DLP] Presidio layers active: "
              + "; ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
              + f"; context enhancer={type(self._analyzer.context_aware_enhancer).__name__}"
              + f"; deny-list terms={len(self.policy.get('deny_list') or [])}"
              + f"; anonymizer=on; PI phrases={len(self._phrases)}")

    # ── policy lookup ────────────────────────────────────────────────────────
    def _meta(self, entity: str) -> dict:
        m = self.policy["entities"].get(entity) or auto_meta(entity, self._layer_hint(entity))
        return {"id": entity, "label": m["label"], "category": m["category"],
                "severity": m["severity"], "action": m["action"]}

    def _layer_hint(self, entity: str) -> str:
        return "NER (spaCy)" if entity in self._ner_entities() else ""

    def _analyze(self, text: str) -> list[RecognizerResult]:
        with self._lock:
            res = self._analyzer.analyze(
                text=text, language="en",
                score_threshold=self.policy.get("score_threshold", 0.5),
                return_decision_process=True)
        return [r for r in res if self._meta(r.entity_type)["action"] != "ignore"]

    # ── proof ────────────────────────────────────────────────────────────────
    def _proof(self, text: str, r: RecognizerResult, occurrences: int) -> dict:
        exp = r.analysis_explanation
        rec_name = (r.recognition_metadata or {}).get("recognizer_name") or (exp.recognizer if exp else "unknown")
        layer = self._layer_of.get(rec_name, "Presidio recognizer")
        stages = [f"{layer}: {rec_name}"]
        boost = round(getattr(exp, "score_context_improvement", 0) or 0, 3) if exp else 0
        ctx_word = getattr(exp, "supportive_context_word", "") if exp else ""
        validated = getattr(exp, "validation_result", None) if exp else None
        if validated is True:
            stages.append("checksum/validator passed")
        if boost > 0:
            stages.append(f"context enhancer +{boost} (word '{ctx_word}')")
        return {
            "engine": "presidio",
            "layer": layer,
            "recognizer": rec_name,
            "entity": r.entity_type,
            "pattern": getattr(exp, "pattern_name", None) if exp else None,
            "original_score": round(getattr(exp, "original_score", r.score), 3) if exp else round(r.score, 3),
            "score": round(r.score, 3),
            "context_boost": boost,
            "context_word": ctx_word or None,
            "checksum_validated": validated,
            "explanation": getattr(exp, "textual_explanation", None) if exp else None,
            "stages": stages,
            "span": [r.start, r.end],
            "preview": preview(text, r.start, r.end),
            "occurrences": occurrences,
        }

    def _hits_from(self, text: str, results: list[RecognizerResult]) -> list[dict]:
        best: dict[str, RecognizerResult] = {}
        count: dict[str, int] = {}
        for r in results:
            count[r.entity_type] = count.get(r.entity_type, 0) + 1
            if r.entity_type not in best or r.score > best[r.entity_type].score:
                best[r.entity_type] = r
        hits = []
        for ent, r in best.items():
            h = self._meta(ent)
            h["score"] = round(r.score, 3)
            h["proof"] = self._proof(text, r, count[ent])
            hits.append(h)
        return hits

    # ── DLPEngine-compatible interface ───────────────────────────────────────
    def scan(self, text: str) -> list[dict]:
        return self.scan_ex(text)[0]

    def enforced(self, results: list[RecognizerResult]) -> list[RecognizerResult]:
        """Results whose policy action is redact or block (used for image boxes)."""
        return [r for r in results if ACTION_RANK.get(self._meta(r.entity_type)["action"], 0) >= 1]

    def scan_ex(self, text: str) -> tuple[list[dict], list[RecognizerResult]]:
        """scan() plus the raw RecognizerResults (spans) for callers that need them."""
        results = self._analyze(text)
        hits = self._hits_from(text, results)
        low = text.lower()
        for ph in self._phrases:
            i = low.find(ph)
            if i >= 0:
                hits.append({
                    "id": "PI_PHRASE:" + ph[:40], "label": f"Injection phrase: {ph}",
                    "category": "prompt_injection", "severity": "medium", "action": "warn",
                    "proof": {"engine": "heuristic", "layer": "Phrase heuristic (jailbreak_phrases.txt)",
                              "recognizer": "substring_match", "pattern": ph, "score": 1.0,
                              "explanation": f"Prompt contains the known jailbreak phrase '{ph}'",
                              "stages": ["phrase list match"], "span": [i, i + len(ph)],
                              "preview": text[i:i + len(ph)][:40]}})
        return hits, results

    def redact(self, text: str) -> tuple[str, list[dict]]:
        results = [r for r in self._analyze(text) if ACTION_RANK.get(self._meta(r.entity_type)["action"], 0) >= 1]
        if not results:
            return text, []
        ops = {r.entity_type: OperatorConfig("replace", {"new_value": f"[REDACTED:{r.entity_type}]"})
               for r in results}
        out = self._anonymizer.anonymize(
            text=text, operators=ops,
            analyzer_results=[AnonResult(r.entity_type, r.start, r.end, r.score) for r in results])
        hits = self._hits_from(text, results)
        for h in hits:
            h["action"] = "redact"
            h["proof"]["stages"].append("Presidio AnonymizerEngine: replace operator applied")
        return out.text, hits

    def worst_action(self, hits: list[dict]) -> str:
        if not hits:
            return "none"
        return max(hits, key=lambda h: ACTION_RANK.get(h["action"], 0))["action"]

    def escalate(self, hits: list[dict]) -> list[dict]:
        pi = [h for h in hits if h["category"] == "prompt_injection"]
        if len(pi) >= PROMPT_INJECTION_ESCALATION_THRESHOLD:
            for h in pi:
                h["action"], h["escalated"] = "block", True
                h.setdefault("proof", {}).setdefault("stages", []).append(
                    f"escalated: {len(pi)} prompt-injection signals in one request")
        return hits
