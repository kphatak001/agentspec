"""OWASP-AGENT-05: Inadequate Sandboxing analysis."""

from __future__ import annotations
from ..model import Architecture, Finding

_EXEC_TOOLS = {"execute_bash", "shell", "run_command", "terminal", "subprocess"}


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        exec_tools = [t for t in agent.tools if t.type == "execute" or t.name.lower() in _EXEC_TOOLS]
        if exec_tools:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-05",
                owasp_name="Inadequate Sandboxing",
                severity="HIGH",
                title=f"No sandbox for execution tools on '{agent.name}'",
                description=f"Agent '{agent.name}' has execution tools ({', '.join(t.name for t in exec_tools)}) "
                            "with no container or sandbox configuration detected.",
                attack_scenario="Arbitrary command execution escapes to host system. "
                                "No resource limits prevent fork bombs or disk exhaustion.",
                affected=agent.name,
                mitigation="Run execution tools inside nsjail, firejail, or a container. "
                           "Add resource limits (CPU, memory, disk, network).",
                score=70.0,
            ))

        outside_project = [t for t in agent.tools if t.type in ("read", "write") and t.scope == "*"]
        if outside_project:
            findings.append(Finding(
                owasp_id="OWASP-AGENT-05",
                owasp_name="Inadequate Sandboxing",
                severity="MEDIUM",
                title=f"Unrestricted filesystem access on '{agent.name}'",
                description=f"Agent '{agent.name}' has {len(outside_project)} tool(s) with unrestricted "
                            "filesystem scope. Can access files outside project directory.",
                attack_scenario="Agent reads sensitive files (SSH keys, env files, credentials) outside project.",
                affected=agent.name,
                mitigation="Restrict tool scope to project directory. Use allowedPaths.",
                score=50.0,
            ))
    return findings
