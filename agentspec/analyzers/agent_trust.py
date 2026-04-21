"""OWASP-AGENT-06: Implicit Trust Between Agents analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    if len(arch.agents) < 2:
        return findings

    agent_map = {a.name: a for a in arch.agents}

    for agent in arch.agents:
        for delegate_name in agent.delegates_to:
            delegate = agent_map.get(delegate_name)
            if not delegate:
                continue

            if not agent.output_validated:
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-06",
                    owasp_name="Implicit Trust Between Agents",
                    severity="MEDIUM",
                    title=f"'{agent.name}' trusts '{delegate_name}' output without validation",
                    description=f"Agent '{agent.name}' delegates to '{delegate_name}' with output_validated: false.",
                    attack_scenario="Compromised subagent returns malicious instructions that parent executes.",
                    affected=f"{agent.name} → {delegate_name}",
                    mitigation="Validate subagent output before acting on it.",
                    score=55.0,
                ))

            parent_types = {t.type for t in agent.tools}
            child_types = {t.type for t in delegate.tools}
            escalation = child_types - parent_types
            if escalation & {"write", "execute"}:
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-06",
                    owasp_name="Implicit Trust Between Agents",
                    severity="HIGH",
                    title=f"Subagent '{delegate_name}' has broader permissions than parent",
                    description=f"Subagent '{delegate_name}' has {escalation} capabilities "
                                f"that parent '{agent.name}' lacks. Privilege escalation risk.",
                    attack_scenario="Parent delegates to subagent which has more destructive capabilities.",
                    affected=f"{agent.name} → {delegate_name}",
                    mitigation="Ensure subagents have equal or fewer permissions than their parent.",
                    score=70.0,
                ))
    return findings
