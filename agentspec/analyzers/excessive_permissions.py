"""OWASP-AGENT-03: Excessive Permissions analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        auto_write_exec = [t for t in agent.tools if t.auto_approved and t.type in ("write", "execute")]
        if auto_write_exec:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-03",
                owasp_name="Excessive Permissions",
                severity="CRITICAL",
                title=f"Write/execute tools auto-approved on '{agent.name}'",
                description=f"Agent '{agent.name}' has {len(auto_write_exec)} destructive tool(s) in auto-approved list: "
                            f"{', '.join(t.name for t in auto_write_exec)}. No human approval required.",
                attack_scenario="Prompt injection triggers destructive tool calls without user awareness.",
                affected=agent.name,
                mitigation="Remove write/execute tools from auto-approved list. Require human approval for destructive operations.",
                score=90.0,
            ))

        total = len(agent.tools)
        auto = sum(1 for t in agent.tools if t.auto_approved)
        if total > 10 and auto > total * 0.5:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-03",
                owasp_name="Excessive Permissions",
                severity="HIGH",
                title=f"Broad auto-approval on '{agent.name}' ({auto}/{total} tools)",
                description=f"Agent '{agent.name}' has {total} tools with {auto} auto-approved. "
                            "Large attack surface with minimal human oversight.",
                attack_scenario="Multi-step exploitation across many auto-approved tools without user awareness.",
                affected=agent.name,
                mitigation="Reduce auto-approved tools to read-only operations. Apply principle of least privilege.",
                score=65.0,
            ))

        mcp_tools = [t for t in agent.tools if t.mcp_server]
        servers: dict[str, list] = {}
        for t in mcp_tools:
            servers.setdefault(t.mcp_server, []).append(t)
        for srv, tools in servers.items():
            if len(tools) > 10:
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-03",
                    owasp_name="Excessive Permissions",
                    severity="MEDIUM",
                    title=f"MCP server '{srv}' exposes {len(tools)} tools",
                    description=f"MCP server '{srv}' on agent '{agent.name}' provides {len(tools)} tools. "
                                "Broad tool sets increase attack surface.",
                    attack_scenario="Attacker exploits one of many available tools for lateral movement.",
                    affected=f"{agent.name}/{srv}",
                    mitigation=f"Filter tools from '{srv}' to only those needed. Use allowedTools.",
                    score=45.0,
                ))
    return findings
