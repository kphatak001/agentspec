"""OWASP Agentic Skills Top 10 (AST10) cross-reference mapping.

Maps existing OWASP Agentic Top 10 findings to AST10 categories,
and adds skill-specific analyzers for risks not covered by the
agent/tool layer analysis.
"""

from __future__ import annotations
from ..model import Architecture, Finding

# ── Cross-reference: OWASP Agentic → AST10 ────────────────────────────────
# Each existing OWASP-AGENT finding maps to one or more AST categories.

AGENT_TO_AST = {
    "OWASP-AGENT-01": ["AST01", "AST04"],  # Prompt Injection → Malicious Skills, Insecure Metadata
    "OWASP-AGENT-02": ["AST03", "AST06"],  # Unsafe Tool Exec → Over-Privileged, Weak Isolation
    "OWASP-AGENT-03": ["AST03"],            # Excessive Permissions → Over-Privileged Skills
    "OWASP-AGENT-04": ["AST04"],            # Output Validation → Insecure Metadata
    "OWASP-AGENT-05": ["AST06"],            # Sandboxing → Weak Isolation
    "OWASP-AGENT-06": ["AST02", "AST10"],   # Agent Trust → Supply Chain, Cross-Platform Reuse
    "OWASP-AGENT-07": ["AST01", "AST05"],   # Insecure Memory → Malicious Skills, Unsafe Deserialization
    "OWASP-AGENT-08": ["AST09"],            # Uncontrolled Autonomy → No Governance
    "OWASP-AGENT-09": ["AST09"],            # Logging → No Governance
    "OWASP-AGENT-10": ["AST06", "AST10"],   # Agent Communication → Weak Isolation, Cross-Platform
}

AST_NAMES = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Unsafe Deserialization",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Add AST10 cross-references to existing findings."""
    for f in findings:
        ast_ids = AGENT_TO_AST.get(f.owasp_id, [])
        if ast_ids:
            refs = ", ".join(f"{aid} ({AST_NAMES[aid]})" for aid in ast_ids)
            f.description += f"\n\n**AST10 cross-ref:** {refs}"
    return findings


# ── Skill-specific analyzers (risks not in OWASP Agentic Top 10) ──────────

def analyze(arch: Architecture) -> list[Finding]:
    """Analyze for AST10-specific risks beyond the agent/tool layer."""
    findings = []

    # AST02: Supply Chain — skills from external/unverified MCP servers
    for agent in arch.agents:
        remote_servers = [t for t in agent.tools if t.mcp_server and
                         not t.mcp_server.startswith(("localhost", "127.0.0.1", "npx", "uvx", "python"))]
        if remote_servers:
            findings.append(Finding(
                owasp_id="AST02",
                owasp_name="Supply Chain Compromise",
                severity="HIGH",
                title=f"Agent '{agent.name}' uses remote MCP servers without provenance verification",
                description=f"Remote MCP servers ({', '.join(t.mcp_server for t in remote_servers)}) "
                            "have no signing or hash verification. A compromised server can inject "
                            "malicious tool responses.",
                attack_scenario="Attacker compromises remote MCP server → injects malicious tool "
                                "responses → agent executes attacker-controlled actions.",
                affected=agent.name,
                mitigation="Pin MCP server versions with content hashes. Use signed skill manifests. "
                           "Prefer local MCP servers over remote endpoints.",
                score=7.5,
            ))

    # AST07: Update Drift — no version pinning detected
    all_tools = [t for a in arch.agents for t in a.tools]
    unpinned_mcp = [t for t in all_tools if t.mcp_server and "@latest" in t.mcp_server]
    if unpinned_mcp:
        findings.append(Finding(
            owasp_id="AST07",
            owasp_name="Update Drift",
            severity="MEDIUM",
            title="MCP servers use @latest without version pinning",
            description=f"Tools using @latest: {', '.join(t.name for t in unpinned_mcp)}. "
                        "Unpinned dependencies can be silently replaced with malicious versions.",
            attack_scenario="Attacker publishes malicious update to MCP server package → "
                            "@latest resolves to compromised version → agent loads malicious tools.",
            affected=", ".join(t.name for t in unpinned_mcp),
            mitigation="Pin MCP server packages to specific versions with hash verification. "
                       "Use lockfiles for npm/pip dependencies.",
            score=5.0,
        ))

    # AST08: Poor Scanning — architecture has no scan/validation metadata
    if not arch.logging.get("skill_scanning"):
        findings.append(Finding(
            owasp_id="AST08",
            owasp_name="Poor Scanning",
            severity="MEDIUM",
            title="No skill scanning or validation configured",
            description="The agent architecture has no skill scanning, manifest validation, "
                        "or provenance checking configured. Pattern-matching scanners alone "
                        "miss the majority of threats that use natural-language instruction manipulation.",
            attack_scenario="Malicious skill passes basic pattern matching → executes "
                            "data exfiltration via natural-language instructions in SKILL.md.",
            affected="all agents",
            mitigation="Implement behavioral scanning at install time. Use agentspec for "
                       "static analysis. Add scan_status to skill manifests.",
            score=4.5,
        ))

    return findings
