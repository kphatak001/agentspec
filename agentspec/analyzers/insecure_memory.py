"""OWASP-AGENT-07: Insecure Memory/RAG analysis."""

from __future__ import annotations
from ..model import Architecture, Finding


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    if not arch.memory_sources:
        return findings

    for src in arch.memory_sources:
        if src.type == "external" and not src.content_validated:
            has_write_exec = any(
                t.type in ("write", "execute")
                for a in arch.agents for t in a.tools
            )
            sev = "HIGH" if has_write_exec else "MEDIUM"
            score = 75.0 if has_write_exec else 45.0
            findings.append(Finding(
                owasp_id="OWASP-AGENT-07",
                owasp_name="Insecure Memory/RAG",
                severity=sev,
                title=f"Unvalidated external RAG source '{src.name}'",
                description=f"Memory source '{src.name}' ingests from external source without content validation.",
                attack_scenario="Attacker edits external source → indirect prompt injection via RAG.",
                affected=src.name,
                mitigation="Pin RAG sources to trusted authors. Add content hash validation.",
                score=score,
            ))

        if src.writable:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-07",
                owasp_name="Insecure Memory/RAG",
                severity="HIGH",
                title=f"Writable memory source '{src.name}'",
                description=f"Memory source '{src.name}' is writable. Agent can modify its own context.",
                attack_scenario="Agent is tricked into writing poisoned data to memory, affecting future runs.",
                affected=src.name,
                mitigation="Make memory sources read-only. Use separate write path with validation.",
                score=70.0,
            ))
    return findings
