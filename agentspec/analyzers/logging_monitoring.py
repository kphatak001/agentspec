"""OWASP-AGENT-09: Inadequate Logging & Monitoring analysis."""

from __future__ import annotations
from ..model import Architecture, Finding

_EXPECTED_KEYS = {"tool_calls", "agent_decisions", "output_content"}


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    log = arch.logging

    if not log:
        findings.append(Finding(
            owasp_id="OWASP-AGENT-09",
            owasp_name="Inadequate Logging & Monitoring",
            severity="MEDIUM",
            title="No logging configuration",
            description="No logging section found in architecture config.",
            attack_scenario="Attacks go undetected. No audit trail for forensics.",
            affected="architecture",
            mitigation="Add logging config: tool_calls: true, agent_decisions: true, output_content: true.",
            score=50.0,
        ))
        return findings

    disabled = [k for k in _EXPECTED_KEYS if not log.get(k, False)]
    missing = [k for k in _EXPECTED_KEYS if k not in log]

    if disabled:
        findings.append(Finding(
            owasp_id="OWASP-AGENT-09",
            owasp_name="Inadequate Logging & Monitoring",
            severity="MEDIUM" if "tool_calls" not in disabled else "HIGH",
            title=f"Logging disabled for: {', '.join(disabled)}",
            description=f"Logging is disabled for: {', '.join(disabled)}. "
                        "Incomplete audit trail.",
            attack_scenario="Attacker actions not logged. Forensic investigation hampered.",
            affected="architecture",
            mitigation=f"Enable logging for: {', '.join(disabled)}.",
            score=55.0 if "tool_calls" in disabled else 40.0,
        ))

    if missing:
        findings.append(Finding(
            owasp_id="OWASP-AGENT-09",
            owasp_name="Inadequate Logging & Monitoring",
            severity="LOW",
            title=f"Missing logging keys: {', '.join(missing)}",
            description=f"Logging config missing keys: {', '.join(missing)}.",
            attack_scenario="Gaps in audit coverage.",
            affected="architecture",
            mitigation=f"Add missing logging keys: {', '.join(missing)}.",
            score=20.0,
        ))
    return findings
