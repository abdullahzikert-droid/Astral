"""
analyzer — Claude-powered security analysis for the scanner tab.

Sends detected tools + NHIs to claude-sonnet-4-6 and returns structured
isolation recommendations that the dashboard renders as actionable permit
suggestions (fs_rules + network config) the user can create in one click.
"""
from __future__ import annotations

import json
import os
from typing import Optional

_SYSTEM = """You are a security architect specialising in NHI (non-human identity)
sandboxing for AI agents, IDE plugins, and developer tools.

Given a JSON list of detected tools on a developer's machine, return ONLY a
single JSON object — no markdown fences, no preamble, no trailing text.

Schema:
{
  "risk_summary": "1-2 sentence overall posture assessment",
  "tool_assessments": [
    {
      "tool_id":   "<id field from input>",
      "tool_name": "<name>",
      "category":  "<category from input>",
      "risk_level": "high | medium | low",
      "concerns": ["specific concern", "..."],
      "recommended_profiles": [
        {
          "level": "strict",
          "label": "Label ≤ 40 chars",
          "description": "One sentence on what this allows and why",
          "fs_rules": [{"path": "/path", "mode": "read | write | read_write", "is_file": false}],
          "network": {"mode": "block | proxy | open", "allowed_hosts": []}
        },
        { "level": "balanced",   "label": "...", "description": "...", "fs_rules": [...], "network": {...} },
        { "level": "permissive", "label": "...", "description": "...", "fs_rules": [...], "network": {...} }
      ]
    }
  ],
  "nhi_assessments": [
    {
      "name": "<NHI name from input>",
      "risk_level": "high | medium | low",
      "concerns": ["..."],
      "recommended_action": "Short imperative action (≤ 60 chars)"
    }
  ],
  "global_recommendations": [
    "Concrete recommendation",
    "..."
  ]
}

Rules:
- Include ALL tools supplied — even low-risk ones need an assessment entry.
- Each tool MUST have exactly 3 recommended_profiles (strict, balanced, permissive).
- Use realistic macOS paths: /tmp for scratch, ~/Library/Application Support/<App>
  for app configs, ~/.ssh for credentials, ~/.aws for cloud creds.
  The path /path/to/workspace is never acceptable — use real macOS paths.
- network.allowed_hosts is populated ONLY when mode=proxy; otherwise [].
- Concerns must be specific: "Can read ~/.aws/credentials" not "security risk".
- AI-enhanced tools (Cursor, Copilot, Claude CLI…) should always be high or medium.
- Local model runners (Ollama, LM Studio…) are medium — no network key exfil risk.
- VS Code extensions that phone home are at least medium.
- Python SDK packages (openai, anthropic…) are medium — depend on which agent uses them.
- Return ONLY the JSON object. Any other text will break parsing.
"""


def analyze_tools(tools: list[dict], nhis: list[dict]) -> dict:
    """
    Call claude-sonnet-4-6 with the scanned tool inventory and get back
    structured isolation recommendations per tool + NHI.

    Falls back gracefully if ANTHROPIC_API_KEY is absent or anthropic
    package is not installed.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return _missing_key_response()

    try:
        import anthropic  # lazy import — not a hard dep for the rest of sentinel
    except ImportError:
        return _import_error_response()

    try:
        client = anthropic.Anthropic(api_key=api_key)
        payload = json.dumps({"tools": tools, "nhis": nhis}, indent=2)
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=_SYSTEM,
            messages=[{
                "role": "user",
                "content": (
                    "Analyze these detected AI/dev tools and NHIs and return isolation "
                    f"recommendations as described:\n\n{payload}"
                ),
            }],
        )
        raw = msg.content[0].text.strip()

        # Strip any accidental markdown fences the model might emit
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.lower().startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        if raw.endswith("```"):
            raw = raw[:-3].strip()

        return json.loads(raw)

    except json.JSONDecodeError as exc:
        return {"error": f"Claude returned unparseable JSON: {exc}", **_empty_body()}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), **_empty_body()}


# ------------------------------------------------------------------ fallbacks

def _empty_body() -> dict:
    return {
        "risk_summary": "Analysis unavailable.",
        "tool_assessments": [],
        "nhi_assessments": [],
        "global_recommendations": [],
    }


def _missing_key_response() -> dict:
    return {
        **_empty_body(),
        "error": "no_key",
        "risk_summary": (
            "Set the ANTHROPIC_API_KEY environment variable to enable "
            "AI-powered isolation recommendations."
        ),
        "global_recommendations": [
            "Export ANTHROPIC_API_KEY before starting Sentinel to unlock AI analysis.",
            "Without analysis, create permits manually via the Permits tab.",
        ],
    }


def _import_error_response() -> dict:
    return {
        **_empty_body(),
        "error": "no_package",
        "risk_summary": "Run 'pip install anthropic' then restart Sentinel to enable AI analysis.",
        "global_recommendations": [
            "Install the anthropic Python package: pip install anthropic",
        ],
    }
