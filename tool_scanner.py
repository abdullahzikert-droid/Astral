"""
tool_scanner.py — macOS AI/dev tool inventory scanner for Apexion client.

Checks for installed AI assistants, IDEs, CLI tools, VS Code extensions,
and Python packages that are relevant to AI/LLM usage.
macOS only — uses /Applications, ~/Library/Application Support, plist files.
"""

import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Optional

HOME   = Path.home()
APPS   = Path("/Applications")
APPSUPP = HOME / "Library" / "Application Support"
VSEXT  = HOME / ".vscode" / "extensions"
VSEXT2 = HOME / ".cursor" / "extensions"   # Cursor also uses VSCode extension format


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _app_version(app_name: str) -> Optional[str]:
    """Read CFBundleShortVersionString from an .app's Info.plist."""
    plist_path = APPS / f"{app_name}.app" / "Contents" / "Info.plist"
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        return data.get("CFBundleShortVersionString") or data.get("CFBundleVersion")
    except Exception:
        return None


def _app(app_name: str, display_name: str, category: str, note: str = "") -> Optional[dict]:
    """Return a tool entry if an .app bundle exists in /Applications."""
    path = APPS / f"{app_name}.app"
    if not path.exists():
        return None
    ver = _app_version(app_name)
    return {
        "id":       app_name.lower().replace(" ", "_"),
        "name":     display_name,
        "category": category,
        "version":  ver or "installed",
        "path":     str(path),
        "note":     note,
    }


def _dir(label: str, display_name: str, category: str, *paths: Path, note: str = "") -> Optional[dict]:
    """Return a tool entry if any of the given directories exist."""
    for path in paths:
        if path.exists():
            return {
                "id":       label,
                "name":     display_name,
                "category": category,
                "version":  "configured",
                "path":     str(path),
                "note":     note,
            }
    return None


def _cli(cmd: str, display_name: str, category: str, version_flag: str = "--version", note: str = "") -> Optional[dict]:
    """Return a tool entry if a CLI binary is on PATH."""
    binary = shutil.which(cmd)
    if not binary:
        return None
    ver = "found"
    try:
        out = subprocess.check_output(
            [binary, version_flag], stderr=subprocess.STDOUT, timeout=3, text=True
        )
        ver = out.strip().split("\n")[0][:80]
    except Exception:
        pass
    return {
        "id":       cmd,
        "name":     display_name,
        "category": category,
        "version":  ver,
        "path":     binary,
        "note":     note,
    }


def _pip_pkg(pkg_import: str, display_name: str, note: str = "") -> Optional[dict]:
    """Return a tool entry if a Python package is importable."""
    try:
        spec = importlib.util.find_spec(pkg_import)
    except (ImportError, ValueError):   # dotted name whose parent package isn't installed
        spec = None
    if spec is None:
        return None
    ver = "installed"
    try:
        from importlib.metadata import version as _ver
        ver = _ver(pkg_import.replace("_", "-"))
    except Exception:
        try:
            from importlib.metadata import version as _ver
            ver = _ver(pkg_import)
        except Exception:
            pass
    return {
        "id":       pkg_import,
        "name":     display_name,
        "category": "Python Package",
        "version":  ver,
        "path":     spec.origin or "installed",
        "note":     note,
    }


def _vscode_ext(ext_prefix: str, display_name: str, note: str = "") -> Optional[dict]:
    """Return a tool entry if a VS Code extension directory matching prefix exists."""
    for ext_dir in (VSEXT, VSEXT2):
        if not ext_dir.exists():
            continue
        try:
            for entry in ext_dir.iterdir():
                if entry.name.lower().startswith(ext_prefix.lower()):
                    # Try to read version from package.json
                    ver = "installed"
                    pkg = entry / "package.json"
                    if pkg.exists():
                        try:
                            d = json.loads(pkg.read_text(errors="replace"))
                            ver = d.get("version", "installed")
                        except Exception:
                            pass
                    return {
                        "id":       ext_prefix,
                        "name":     display_name,
                        "category": "VS Code Extension",
                        "version":  ver,
                        "path":     str(entry),
                        "note":     note,
                    }
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main scan
# ─────────────────────────────────────────────────────────────────────────────


# ── NHI Scanner ────────────────────────────────────────────────────────
def scan_nhis() -> list[dict]:
    nhis = []
    
    # Check AWS credentials
    aws_creds = HOME / ".aws" / "credentials"
    if aws_creds.exists():
        try:
            content = aws_creds.read_text()
            keys = content.count("aws_access_key_id")
            if keys > 0:
                nhis.append({
                    "name": "AWS Local Profile",
                    "type": "Environment",
                    "active_keys": keys,
                    "risk_score": 65
                })
        except Exception:
            pass
            
    # Check SSH keys
    ssh_dir = HOME / ".ssh"
    if ssh_dir.exists():
        try:
            keys = 0
            for file in ssh_dir.iterdir():
                if file.is_file() and not file.name.endswith(".pub") and "known_hosts" not in file.name:
                    keys += 1
            if keys > 0:
                nhis.append({
                    "name": "Local SSH Keys",
                    "type": "Environment",
                    "active_keys": keys,
                    "risk_score": 40
                })
        except Exception:
            pass

    # Check NPM config
    npmrc = HOME / ".npmrc"
    if npmrc.exists():
        try:
            if "authToken" in npmrc.read_text():
                nhis.append({
                    "name": "NPM Auth Token",
                    "type": "CI/CD",
                    "active_keys": 1,
                    "risk_score": 50
                })
        except Exception:
            pass

    return nhis

def scan() -> dict:
    """Scan the macOS system and return a dict of detected AI/dev tools and NHIs."""

    results = []

    def add(entry):
        if entry:
            results.append(entry)

    # ── AI Desktop Apps ────────────────────────────────────────────────────
    add(_app("Claude",   "Claude Desktop",  "AI Assistant",
             note="Anthropic Claude — local desktop client"))
    add(_app("ChatGPT",  "ChatGPT Desktop", "AI Assistant",
             note="OpenAI ChatGPT desktop app"))
    add(_app("Perplexity", "Perplexity",    "AI Assistant",
             note="Perplexity AI search assistant"))
    add(_app("Poe",      "Poe",             "AI Assistant",
             note="Quora Poe — multi-model AI chat"))
    add(_app("Gemini",   "Gemini",          "AI Assistant",
             note="Google Gemini desktop app"))
    add(_app("Copilot",  "Microsoft Copilot", "AI Assistant",
             note="Microsoft Copilot desktop"))
    add(_app("LM Studio", "LM Studio",      "AI Assistant",
             note="Local LLM runner — supports Llama, Mistral, etc."))
    add(_app("Jan",      "Jan",             "AI Assistant",
             note="Local AI chat with Llama, Mistral, etc."))
    add(_app("Msty",     "Msty",            "AI Assistant",
             note="Msty — local model runner"))
    add(_app("Anything LLM", "AnythingLLM", "AI Assistant",
             note="AnythingLLM — multi-model chat with RAG"))
    add(_app("Diffusion Bee", "DiffusionBee", "AI Assistant",
             note="Stable Diffusion GUI for macOS"))

    # ── AI-Enhanced IDEs ───────────────────────────────────────────────────
    add(_app("Cursor",   "Cursor",          "AI IDE",
             note="AI-first fork of VS Code — built-in GPT-4 Turbo"))
    add(_app("Windsurf", "Windsurf",        "AI IDE",
             note="Codeium's AI IDE — Cascade agentic coding"))
    add(_app("Visual Studio Code", "VS Code", "IDE",
             note="Microsoft VS Code"))
    add(_app("Xcode",    "Xcode",           "IDE",
             note="Apple Xcode (includes AI suggestions in Xcode 16+)"))
    add(_app("Positron", "Positron",        "IDE",
             note="Data science IDE based on VS Code"))
    add(_app("Zed",      "Zed",             "IDE",
             note="Zed editor — has built-in AI assistant"))
    add(_app("Warp",     "Warp",            "Terminal",
             note="AI-powered terminal with natural language commands"))
    add(_app("iTerm",    "iTerm2",          "Terminal",
             note="iTerm2 terminal emulator"))

    # JetBrains IDEs
    for ide_name, display in [
        ("PyCharm",          "PyCharm"),
        ("PyCharm CE",       "PyCharm CE"),
        ("IntelliJ IDEA",    "IntelliJ IDEA"),
        ("WebStorm",         "WebStorm"),
        ("DataGrip",         "DataGrip"),
        ("GoLand",           "GoLand"),
        ("RubyMine",         "RubyMine"),
        ("CLion",            "CLion"),
        ("DataSpell",        "DataSpell"),
        ("Fleet",            "JetBrains Fleet"),
        ("JetBrains Toolbox","JetBrains Toolbox"),
    ]:
        add(_app(ide_name, display, "IDE",
                 note="JetBrains IDE (AI Assistant plugin available)"))

    # Amazon Q (ex-CodeWhisperer)
    add(_app("Amazon Q", "Amazon Q", "AI Assistant",
             note="Amazon Q Developer — AI coding assistant"))

    # ── CLI AI Tools ───────────────────────────────────────────────────────
    add(_cli("ollama",  "Ollama",          "CLI Tool", "list",
             note="Local model runner — Llama 3, Mistral, Phi-3, etc."))
    add(_cli("aider",   "Aider",           "CLI Tool",
             note="AI pair programmer in the terminal"))
    add(_cli("llm",     "LLM CLI",         "CLI Tool",
             note="Simon Willison's llm CLI — unified model interface"))
    add(_cli("sgpt",    "Shell-GPT",       "CLI Tool",
             note="GPT-powered shell commands and chat"))
    add(_cli("fabric",  "Fabric",          "CLI Tool",
             note="AI augmentation framework for pipelines"))
    add(_cli("claude",  "Claude CLI",      "CLI Tool",
             note="Anthropic Claude CLI / SDK"))
    add(_cli("openai",  "OpenAI CLI",      "CLI Tool",
             note="OpenAI Python library CLI"))
    add(_cli("copilot", "GitHub Copilot CLI", "CLI Tool",
             note="GitHub Copilot CLI (gh extension)"))
    add(_cli("codeium", "Codeium CLI",     "CLI Tool",
             note="Codeium CLI tool"))
    add(_cli("continue","Continue CLI",    "CLI Tool",
             note="Continue dev tool CLI"))

    # Ollama config dir
    add(_dir("ollama_models", "Ollama Models", "CLI Tool",
             HOME / ".ollama",
             note="Ollama local model storage (~/.ollama)"))

    # ── VS Code Extensions ─────────────────────────────────────────────────
    add(_vscode_ext("github.copilot",           "GitHub Copilot",
                    note="OpenAI Codex-based code completion"))
    add(_vscode_ext("codeium.codeium",          "Codeium",
                    note="Free AI code completion"))
    add(_vscode_ext("tabnine.tabnine-vscode",   "Tabnine",
                    note="AI code completion — local + cloud models"))
    add(_vscode_ext("continue.continue",        "Continue",
                    note="Open-source AI coding assistant extension"))
    add(_vscode_ext("amazon.codewhisperer",     "Amazon CodeWhisperer",
                    note="AWS AI code suggestions"))
    add(_vscode_ext("amazonwebservices.aws-toolkit", "AWS Toolkit",
                    note="AWS Toolkit (includes Q Developer)"))
    add(_vscode_ext("google.geminicodeassist",  "Gemini Code Assist",
                    note="Google Gemini-powered code suggestions"))
    add(_vscode_ext("google.cloudcode",         "Google Cloud Code",
                    note="Google Cloud Code extension"))
    add(_vscode_ext("sourcegraph.cody-ai",      "Sourcegraph Cody",
                    note="Sourcegraph Cody AI coding assistant"))
    add(_vscode_ext("anysphere.cursor-always",  "Cursor (VSCode ext)",
                    note="Cursor AI extension for VS Code"))
    add(_vscode_ext("supermaven",               "Supermaven",
                    note="Supermaven AI autocomplete"))
    add(_vscode_ext("codestory",                "CodeStory / Aide",
                    note="Aide AI coding assistant"))
    add(_vscode_ext("blackboxapp",              "Blackbox AI",
                    note="Blackbox AI code assistant"))
    add(_vscode_ext("mintlify",                 "Mintlify Doc Writer",
                    note="AI documentation writer"))
    add(_vscode_ext("statelyai",                "Stately AI",
                    note="Stately AI statechart assistant"))

    # ── Python AI Packages ─────────────────────────────────────────────────
    packages = [
        ("openai",          "openai",           "OpenAI SDK"),
        ("anthropic",       "anthropic",        "Anthropic SDK"),
        ("langchain",       "langchain",        "LangChain framework"),
        ("langchain_core",  "langchain_core",   "LangChain Core"),
        ("llama_index",     "llama_index",      "LlamaIndex (RAG framework)"),
        ("transformers",    "transformers",     "HuggingFace Transformers"),
        ("ollama",          "ollama",           "Ollama Python client"),
        ("litellm",         "litellm",          "LiteLLM (unified API)"),
        ("autogen",         "autogen",          "AutoGen (Microsoft multi-agent)"),
        ("crewai",          "crewai",           "CrewAI (agent orchestration)"),
        ("instructor",      "instructor",       "Instructor (structured LLM output)"),
        ("outlines",        "outlines",         "Outlines (structured generation)"),
        ("guidance",        "guidance",         "Guidance (Microsoft LLM control)"),
        ("haystack",        "haystack",         "Haystack NLP framework"),
        ("cohere",          "cohere",           "Cohere SDK"),
        ("groq",            "groq",             "Groq SDK"),
        ("mistralai",       "mistralai",        "Mistral AI SDK"),
        ("google.generativeai", "google-generativeai", "Google Generative AI SDK"),
        ("boto3",           "boto3",            "AWS SDK (Bedrock access)"),
        ("tiktoken",        "tiktoken",         "OpenAI Tiktoken (tokenizer)"),
        ("sentence_transformers", "sentence-transformers", "Sentence Transformers"),
    ]
    for import_name, pkg_name, display_name in packages:
        entry = _pip_pkg(import_name, display_name)
        if entry:
            add(entry)

    # ── Config / credential files ──────────────────────────────────────────
    add(_dir("claude_config", "Claude Desktop Config", "Config",
             APPSUPP / "Claude",
             note="Claude Desktop configuration & conversation history"))
    add(_dir("cursor_config", "Cursor Config", "Config",
             HOME / ".cursor",
             note="Cursor IDE user settings"))
    add(_dir("continue_config", "Continue Config", "Config",
             HOME / ".continue",
             APPSUPP / "Continue",
             note="Continue extension configuration"))
    add(_dir("windsurf_config", "Windsurf Config", "Config",
             APPSUPP / "Windsurf",
             note="Windsurf IDE settings"))
    add(_dir("lmstudio_config", "LM Studio Config", "Config",
             HOME / ".lmstudio",
             APPSUPP / "LM-Studio",
             note="LM Studio model settings"))
    add(_dir("jan_config", "Jan Config", "Config",
             HOME / ".jan",
             note="Jan local AI settings & models"))

    return {"tools": results, "nhis": scan_nhis()}


if __name__ == "__main__":
    data = scan()
    tools = data["tools"]
    nhis = data["nhis"]
    print(f"Found {len(tools)} tools and {len(nhis)} NHIs:\n")
    for t in tools:
        print(f"  [{t['category']}] {t['name']} {t['version']} — {t['path']}")
    for n in nhis:
        print(f"  [NHI] {n['name']} ({n['type']}) — {n['active_keys']} keys")
