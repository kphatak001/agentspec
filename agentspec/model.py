"""Internal architecture model and threat model dataclasses."""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Tool:
    name: str
    type: str  # read, write, execute, external
    scope: str = "*"  # path glob, "*" for unrestricted
    auto_approved: bool = False
    mcp_server: str = ""


@dataclass
class Agent:
    name: str
    model: str = ""
    tools: list[Tool] = field(default_factory=list)
    delegates_to: list[str] = field(default_factory=list)
    output_validated: bool = False
    system_prompt: str = ""


@dataclass
class MemorySource:
    name: str
    type: str  # local_files, external, database
    writable: bool = False
    content_validated: bool = False


@dataclass
class Architecture:
    name: str
    agents: list[Agent] = field(default_factory=list)
    memory_sources: list[MemorySource] = field(default_factory=list)
    logging: dict = field(default_factory=dict)
    human_in_the_loop: dict = field(default_factory=dict)


@dataclass
class Finding:
    owasp_id: str  # "OWASP-AGENT-03"
    owasp_name: str  # "Excessive Permissions"
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    attack_scenario: str
    affected: str  # Which agent/tool/source
    mitigation: str
    score: float = 0.0


@dataclass
class ThreatModel:
    architecture: Architecture
    findings: list[Finding] = field(default_factory=list)
    overall_score: float = 0.0
    overall_rating: str = "LOW"
