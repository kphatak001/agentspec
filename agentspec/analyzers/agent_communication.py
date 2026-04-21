"""OWASP-AGENT-10: Insecure Agent Communication analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        seen_servers: set[str] = set()
        for tool in agent.tools:
            if not tool.mcp_server or tool.mcp_server in seen_servers:
                continue
            seen_servers.add(tool.mcp_server)
            srv = tool.mcp_server.lower()
            if any(p in srv for p in ("http://", "remote", "cloud")):
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-10",
                    owasp_name="Insecure Agent Communication",
                    severity="HIGH",
                    title=f"Potentially remote MCP server '{tool.mcp_server}'",
                    description=f"MCP server '{tool.mcp_server}' on agent '{agent.name}' "
                                "appears to be remote. Verify TLS and authentication.",
                    attack_scenario="Man-in-the-middle attack on unencrypted MCP communication.",
                    affected=f"{agent.name}/{tool.mcp_server}",
                    mitigation="Use TLS for remote MCP connections. Add mutual authentication.",
                    score=70.0,
                ))
    return findings
