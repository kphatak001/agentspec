"""OWASP-AGENT-08: Uncontrolled Autonomy analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    hitl = arch.human_in_the_loop

    for agent in arch.agents:
        auto_destructive = [t for t in agent.tools if t.auto_approved and t.type in ("write", "execute")]
        if auto_destructive:
            total = len(agent.tools)
            auto = sum(1 for t in agent.tools if t.auto_approved)
            findings.append(Finding(
                owasp_id="OWASP-AGENT-08",
                owasp_name="Uncontrolled Autonomy",
                severity="HIGH",
                title=f"Auto-approved destructive tools on '{agent.name}'",
                description=f"{auto}/{total} tools auto-approved, including destructive: "
                            f"{', '.join(t.name for t in auto_destructive)}. "
                            "No human-in-the-loop for these operations.",
                attack_scenario="Multi-step exploitation without user awareness.",
                affected=agent.name,
                mitigation="Remove write/execute tools from allowedTools. Require approval for destructive ops.",
                score=70.0,
            ))

    if hitl:
        gaps = [k for k, v in hitl.items() if not v]
        if gaps:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-08",
                owasp_name="Uncontrolled Autonomy",
                severity="MEDIUM",
                title=f"Human-in-the-loop gaps: {', '.join(gaps)}",
                description=f"human_in_the_loop is disabled for: {', '.join(gaps)}.",
                attack_scenario="Agent takes irreversible actions in unmonitored categories.",
                affected="architecture",
                mitigation=f"Enable human_in_the_loop for: {', '.join(gaps)}.",
                score=45.0,
            ))
    elif any(t.type in ("write", "execute") for a in arch.agents for t in a.tools):
        findings.append(Finding(
            owasp_id="OWASP-AGENT-08",
            owasp_name="Uncontrolled Autonomy",
            severity="MEDIUM",
            title="No human-in-the-loop configuration",
            description="Architecture has destructive tools but no human_in_the_loop config.",
            attack_scenario="All destructive actions proceed without human oversight.",
            affected="architecture",
            mitigation="Add human_in_the_loop config with destructive_actions: true.",
            score=50.0,
        ))
    return findings
