"""OWASP-AGENT-04: Insufficient Output Validation analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        if agent.delegates_to and not agent.output_validated:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-04",
                owasp_name="Insufficient Output Validation",
                severity="HIGH",
                title=f"Agent '{agent.name}' delegates without output validation",
                description=f"Agent '{agent.name}' delegates to {', '.join(agent.delegates_to)} "
                            "but does not validate subagent output before acting on it.",
                attack_scenario="Compromised subagent returns malicious instructions that parent agent executes.",
                affected=agent.name,
                mitigation="Add output validation/sanitization for subagent responses. "
                           "Set output_validated: true after implementing checks.",
                score=70.0,
            ))
    return findings
