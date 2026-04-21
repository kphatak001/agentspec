"""Parse agent configs, dispatch to format loaders."""

from __future__ import annotations
import json
from .model import Architecture
from .formats import agentspec_yaml, kiro_json, crewai_yaml, claude_code_json, openai_agents_py


def parse(path: str, fmt: str = "auto") -> Architecture:
    if fmt == "auto":
        fmt = _detect_format(path)
    loaders = {
        "agentspec": agentspec_yaml.parse,
        "kiro": kiro_json.parse,
        "crewai": crewai_yaml.parse,
        "claude-code": claude_code_json.parse,
        "openai-agents": openai_agents_py.parse,
    }
    loader = loaders.get(fmt)
    if not loader:
        raise ValueError(f"Unknown format: {fmt}. Supported: {', '.join(loaders)}")
    return loader(path)


def _detect_format(path: str) -> str:
    if path.endswith(".py"):
        with open(path) as f:
            content = f.read(1024)
        if "from agents" in content or "import Agent" in content or "function_tool" in content:
            return "openai-agents"
        return "openai-agents"  # best guess for .py

    if path.endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        if "permissions" in data or "defaultMode" in data:
            return "claude-code"
        if "allowedTools" in data or "mcpServers" in data:
            return "kiro"
        return "agentspec"

    # YAML files
    with open(path) as f:
        content = f.read(512)
    if "role:" in content and "backstory:" in content:
        return "crewai"
    return "agentspec"
