"""OWASP-AGENT-01: Prompt Injection analysis."""

from __future__ import annotations
from ..model import Architecture, Finding

_EXTERNAL_TOOLS = {"web_search", "url_fetch", "web_fetch", "scrape", "browse", "http_request"}


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        external = [t for t in agent.tools if t.type == "external" or t.name.lower() in _EXTERNAL_TOOLS]
        write_exec = [t for t in agent.tools if t.type in ("write", "execute")]
        rag_sources = [s for s in arch.memory_sources if s.type == "external"]

        if external and write_exec:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-01",
                owasp_name="Prompt Injection",
                severity="CRITICAL",
                title="Indirect prompt injection via external content + write/execute tools",
                description=f"Agent '{agent.name}' fetches external content ({', '.join(t.name for t in external)}) "
                            f"and has write/execute tools ({', '.join(t.name for t in write_exec)}). "
                            "Malicious content from external sources can hijack the agent.",
                attack_scenario="Attacker places prompt injection payload on a web page or document. "
                                "Agent fetches it, follows injected instructions, executes malicious commands.",
                affected=agent.name,
                mitigation="Sanitize external content before processing. Separate content-fetching from "
                           "action-taking into different agents with different permissions.",
                score=95.0,
            ))
        elif external:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-01",
                owasp_name="Prompt Injection",
                severity="MEDIUM",
                title="External content ingestion without write/execute tools",
                description=f"Agent '{agent.name}' fetches external content but lacks destructive tools. "
                            "Risk is data exfiltration or misleading output.",
                attack_scenario="Injected prompt causes agent to leak context or produce misleading responses.",
                affected=agent.name,
                mitigation="Add content validation. Consider instruction hierarchy markers in system prompt.",
                score=40.0,
            ))

        if rag_sources:
            unvalidated = [s for s in rag_sources if not s.content_validated]
            if unvalidated and write_exec:
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-01",
                    owasp_name="Prompt Injection",
                    severity="HIGH",
                    title="Indirect injection via unvalidated RAG sources",
                    description=f"Agent '{agent.name}' has write/execute tools and ingests from unvalidated "
                                f"external RAG sources: {', '.join(s.name for s in unvalidated)}.",
                    attack_scenario="Attacker modifies external RAG source content to include prompt injection.",
                    affected=agent.name,
                    mitigation="Validate RAG source content. Pin to trusted authors. Add content hash checks.",
                    score=75.0,
                ))

    return findings
