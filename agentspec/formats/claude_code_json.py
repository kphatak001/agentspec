"""Parse Claude Code .claude/settings.json into Architecture model.

Claude Code settings use a permission system with allow/deny/ask arrays
containing rules like "Bash", "Bash(npm run *)", "Edit(src/**)",
"WebFetch(domain:example.com)", "mcp__server__tool", "Agent(name)".
"""

from __future__ import annotations
import json
from ..model import Architecture, Agent, Tool, MemorySource


def parse(path: str) -> Architecture:
    with open(path) as f:
        data = json.load(f)

    perms = data.get("permissions", {})
    allow_rules = perms.get("allow", [])
    deny_rules = perms.get("deny", [])
    ask_rules = perms.get("ask", [])

    allowed_set = set(allow_rules)
    mode = perms.get("defaultMode", data.get("defaultMode", "default"))

    tools: list[Tool] = []
    mcp_servers: set[str] = set()

    # Extract tools from all rule lists
    for rule in allow_rules + deny_rules + ask_rules:
        name, specifier = _parse_rule(rule)
        if name.startswith("mcp__"):
            parts = name.split("__")
            srv = parts[1] if len(parts) >= 2 else name
            mcp_servers.add(srv)
            tool_name = "__".join(parts[2:]) if len(parts) >= 3 else name
            if tool_name and tool_name != "*":
                tools.append(Tool(
                    name=rule,
                    type="external",
                    scope=specifier or "*",
                    auto_approved=rule in allowed_set,
                    mcp_server=srv,
                ))
        else:
            ttype = _rule_to_type(name)
            scope = specifier if specifier else "*"
            tools.append(Tool(
                name=rule,
                type=ttype,
                scope=scope,
                auto_approved=rule in allowed_set or _auto_by_mode(mode, ttype),
            ))

    # Deduplicate by rule string
    seen: set[str] = set()
    deduped: list[Tool] = []
    for t in tools:
        if t.name not in seen:
            seen.add(t.name)
            deduped.append(t)

    agent = Agent(
        name=data.get("name", "claude-code"),
        model=data.get("model", ""),
        tools=deduped,
    )

    return Architecture(
        name=agent.name,
        agents=[agent],
        logging={"tool_calls": True, "agent_decisions": True, "output_content": True},
    )


def _parse_rule(rule: str) -> tuple[str, str]:
    """Split 'Bash(npm run *)' into ('Bash', 'npm run *')."""
    if "(" in rule and rule.endswith(")"):
        idx = rule.index("(")
        return rule[:idx], rule[idx + 1:-1]
    return rule, ""


_TYPE_MAP = {
    "bash": "execute",
    "edit": "write",
    "write": "write",
    "read": "read",
    "grep": "read",
    "glob": "read",
    "webfetch": "external",
    "agent": "external",
}


def _rule_to_type(name: str) -> str:
    return _TYPE_MAP.get(name.lower(), "read")


def _auto_by_mode(mode: str, ttype: str) -> bool:
    if mode == "bypassPermissions":
        return True
    if mode == "acceptEdits" and ttype in ("write", "read"):
        return True
    if mode == "auto":
        return True
    return False
