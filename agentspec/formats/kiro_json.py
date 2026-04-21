"""Parse Kiro CLI agent JSON configs into Architecture model."""

from __future__ import annotations
import json
from ..model import Architecture, Agent, Tool


def parse(path: str) -> Architecture:
    with open(path) as f:
        data = json.load(f)

    allowed = set(data.get("allowedTools", []))
    tools = []

    for tn in data.get("tools", []):
        name = tn if isinstance(tn, str) else tn.get("name", "")
        ttype = _infer_type(name)
        tools.append(Tool(
            name=name,
            type=ttype,
            scope="*",
            auto_approved=name in allowed,
        ))

    for mcp in data.get("mcpServers", {}).values():
        for tn in mcp.get("tools", []):
            tools.append(Tool(
                name=tn,
                type="external",
                scope="*",
                auto_approved=tn in allowed,
                mcp_server=mcp.get("name", ""),
            ))

    agent = Agent(
        name=data.get("name", "kiro-agent"),
        model=data.get("model", ""),
        tools=tools,
    )

    return Architecture(name=agent.name, agents=[agent])


_WRITE_TOOLS = {"fs_write", "execute_bash", "write_file", "create_file", "delete_file"}
_EXEC_TOOLS = {"execute_bash", "run_command", "shell", "terminal"}


def _infer_type(name: str) -> str:
    nl = name.lower()
    if nl in _EXEC_TOOLS:
        return "execute"
    if nl in _WRITE_TOOLS or "write" in nl or "create" in nl or "delete" in nl:
        return "write"
    if "search" in nl or "fetch" in nl or "web" in nl:
        return "external"
    return "read"
