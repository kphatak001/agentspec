"""OWASP-AGENT-02: Unsafe Tool Execution analysis."""

from __future__ import annotations
from ..model import Architecture, Finding

_DANGEROUS_TOOLS = {"execute_bash", "shell", "run_command", "terminal", "subprocess"}


def analyze(arch: Architecture) -> list[Finding]:
    findings = []
    for agent in arch.agents:
        for tool in agent.tools:
            if tool.type == "execute" and tool.scope == "*":
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-02",
                    owasp_name="Unsafe Tool Execution",
                    severity="CRITICAL",
                    title=f"Unrestricted command execution via '{tool.name}'",
                    description=f"Tool '{tool.name}' on agent '{agent.name}' has unrestricted command execution. "
                                "No allowedCommands or deniedCommands configured.",
                    attack_scenario="Prompt injection → arbitrary command execution → data exfiltration, "
                                    "reverse shell, or system compromise.",
                    affected=f"{agent.name}/{tool.name}",
                    mitigation=f"Add allowedCommands whitelist to '{tool.name}' or sandbox with nsjail/firejail.",
                    score=95.0,
                ))
            elif tool.type == "write" and tool.scope == "*":
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-02",
                    owasp_name="Unsafe Tool Execution",
                    severity="CRITICAL",
                    title=f"Unrestricted file write via '{tool.name}'",
                    description=f"Tool '{tool.name}' on agent '{agent.name}' can write to any path. "
                                "No allowedPaths configured.",
                    attack_scenario="Agent writes malicious code to ~/.bashrc, crontab, SSH keys, or "
                                    "overwrites critical system files.",
                    affected=f"{agent.name}/{tool.name}",
                    mitigation=f"Add allowedPaths: [\"./project/**\"], deniedPaths: [\"~/.*\", \"/etc/**\"].",
                    score=90.0,
                ))
            elif tool.type in ("write", "execute") and tool.scope != "*":
                findings.append(Finding(
                    owasp_id="OWASP-AGENT-02",
                    owasp_name="Unsafe Tool Execution",
                    severity="LOW",
                    title=f"Scoped {tool.type} tool '{tool.name}'",
                    description=f"Tool '{tool.name}' is scoped to '{tool.scope}'. Verify scope is minimal.",
                    attack_scenario="Path traversal within scope boundary.",
                    affected=f"{agent.name}/{tool.name}",
                    mitigation="Ensure scope doesn't allow traversal (e.g., no '..' in resolved paths).",
                    score=15.0,
                ))
    return findings
