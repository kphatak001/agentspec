"""Parse CrewAI crew YAML configs into Architecture model."""

from __future__ import annotations
import yaml
from ..model import Architecture, Agent, Tool


def parse(path: str) -> Architecture:
    with open(path) as f:
        data = yaml.safe_load(f)

    agents = []
    for ad in data.get("agents", []):
        tools = []
        for tn in ad.get("tools", []):
            name = tn if isinstance(tn, str) else str(tn)
            tools.append(Tool(name=name, type=_infer_type(name), scope="*", auto_approved=True))
        agents.append(Agent(
            name=ad.get("role", ad.get("name", "unnamed")),
            model=ad.get("llm", ""),
            tools=tools,
            delegates_to=[],
        ))

    return Architecture(name=data.get("name", "crewai-crew"), agents=agents)


def _infer_type(name: str) -> str:
    nl = name.lower()
    if "shell" in nl or "bash" in nl or "exec" in nl:
        return "execute"
    if "write" in nl or "create" in nl or "delete" in nl:
        return "write"
    if "search" in nl or "web" in nl or "scrape" in nl:
        return "external"
    return "read"
