"""Run all analyzers, collect findings."""

from __future__ import annotations
from .model import Architecture, Finding
from .analyzers import (
    prompt_injection,
    unsafe_tool_exec,
    excessive_permissions,
    output_validation,
    sandboxing,
    agent_trust,
    insecure_memory,
    uncontrolled_autonomy,
    logging_monitoring,
    agent_communication,
)

_ANALYZERS = [
    prompt_injection,
    unsafe_tool_exec,
    excessive_permissions,
    output_validation,
    sandboxing,
    agent_trust,
    insecure_memory,
    uncontrolled_autonomy,
    logging_monitoring,
    agent_communication,
]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run(arch: Architecture, owasp_filter: set[str] | None = None,
        min_severity: str = "INFO") -> list[Finding]:
    findings: list[Finding] = []
    min_sev = _SEVERITY_ORDER.get(min_severity, 4)

    for analyzer in _ANALYZERS:
        try:
            results = analyzer.analyze(arch)
        except Exception:
            continue
        for f in results:
            if owasp_filter and f.owasp_id.split("-")[-1] not in owasp_filter:
                continue
            if _SEVERITY_ORDER.get(f.severity, 4) <= min_sev:
                findings.append(f)

    findings.sort(key=lambda f: (f.score * -1, _SEVERITY_ORDER.get(f.severity, 4)))
    return findings
