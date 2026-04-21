"""Terminal, JSON, and markdown output for threat models."""

from __future__ import annotations
import json
from dataclasses import asdict
from .model import ThreatModel

_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
_SEP = "═" * 55


def terminal(tm: ThreatModel, verbose: bool = False) -> str:
    arch = tm.architecture
    n_agents = len(arch.agents)
    n_tools = sum(len(a.tools) for a in arch.agents)
    n_mcp = len({t.mcp_server for a in arch.agents for t in a.tools if t.mcp_server})
    n_mem = len(arch.memory_sources)

    lines = [
        "",
        "agentspec threat model",
        _SEP,
        "",
        f"  Architecture: {n_agents} agent{'s' if n_agents != 1 else ''}, "
        f"{n_mcp} MCP server{'s' if n_mcp != 1 else ''}, "
        f"{n_tools} tool{'s' if n_tools != 1 else ''}, "
        f"{n_mem} RAG source{'s' if n_mem != 1 else ''}",
        f"  Risk Score: {tm.overall_score:.0f}/100 ({tm.overall_rating})",
        "",
    ]

    for i, f in enumerate(tm.findings, 1):
        icon = _SEV_ICON.get(f.severity, "⚪")
        lines.append(f"  #{i} {icon} {f.severity} — {f.owasp_name} ({f.owasp_id})")
        lines.append(f"  │ {f.title}")
        lines.append(f"  │ {f.description}")
        if verbose:
            lines.append(f"  │ Attack: {f.attack_scenario}")
        lines.append(f"  │ Fix: {f.mitigation}")
        lines.append(f"  │")

    lines.append(f"  {_SEP}")
    return "\n".join(lines)


def to_json(tm: ThreatModel) -> str:
    return json.dumps(asdict(tm), indent=2)


def to_markdown(tm: ThreatModel) -> str:
    arch = tm.architecture
    n_agents = len(arch.agents)
    n_tools = sum(len(a.tools) for a in arch.agents)

    lines = [
        f"# Threat Model: {arch.name}",
        "",
        f"**Risk Score:** {tm.overall_score:.0f}/100 ({tm.overall_rating})",
        f"**Agents:** {n_agents} | **Tools:** {n_tools} | "
        f"**Memory Sources:** {len(arch.memory_sources)}",
        "",
        "## Findings",
        "",
    ]

    for i, f in enumerate(tm.findings, 1):
        icon = _SEV_ICON.get(f.severity, "⚪")
        lines.append(f"### {i}. {icon} {f.severity} — {f.owasp_name} ({f.owasp_id})")
        lines.append("")
        lines.append(f"**{f.title}**")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")
        lines.append(f"**Attack:** {f.attack_scenario}")
        lines.append("")
        lines.append(f"**Affected:** `{f.affected}`")
        lines.append("")
        lines.append(f"**Mitigation:** {f.mitigation}")
        lines.append("")

    return "\n".join(lines)
