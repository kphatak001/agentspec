"""Generate agent-envelope YAML from agentspec architecture model."""

from __future__ import annotations
import yaml
from .model import Architecture, Finding


# Data sources that are typically sensitive
SENSITIVE_SOURCES = ["customer_db", "customer_account", "secrets", "credentials", "pii"]

# Destinations that should never receive sensitive data
EXTERNAL_DESTINATIONS = ["email_external", "api_external", "file_export", "webhook"]


def emit_envelope(arch: Architecture, findings: list[Finding]) -> str:
    """Generate an agent-envelope YAML from the architecture model.
    
    Maps:
    - Agent tools → allowed workflow steps (glob patterns)
    - Tool types → data flow rules (read sources, write destinations)
    - Agent count → chain depth limit
    - Tool count → budget limits
    - Findings → tighter thresholds for high-risk architectures
    """
    # Collect all tools by type
    read_tools, write_tools, exec_tools = [], [], []
    all_tool_names = []
    for agent in arch.agents:
        for tool in agent.tools:
            all_tool_names.append(tool.name)
            if tool.type == "read":
                read_tools.append(tool.name)
            elif tool.type == "write":
                write_tools.append(tool.name)
            elif tool.type == "execute":
                exec_tools.append(tool.name)

    # Build workflow patterns from tool types
    workflows = []
    if read_tools and write_tools:
        # Common pattern: read → process → write
        read_globs = _to_globs(read_tools)
        write_globs = _to_globs(write_tools)
        workflows.append({
            "name": "read_process_write",
            "steps": read_globs + write_globs,
            "max_steps": min(len(all_tool_names) * 3, 30),
        })
    if read_tools:
        workflows.append({
            "name": "read_only",
            "steps": _to_globs(read_tools),
            "max_steps": 10,
        })

    # Build forbidden data flows
    forbidden_flows = []
    # If there are read tools accessing sensitive data and write tools that go external
    has_sensitive_reads = any(
        any(s in t.name.lower() or s in t.scope.lower() for s in SENSITIVE_SOURCES)
        for a in arch.agents for t in a.tools if t.type == "read"
    )
    has_external_writes = any(
        t.type in ("write", "external") and t.scope == "*"
        for a in arch.agents for t in a.tools
    )

    if has_sensitive_reads and has_external_writes:
        for source in SENSITIVE_SOURCES:
            forbidden_flows.append({"from": source, "to": EXTERNAL_DESTINATIONS})

    # If findings indicate excessive permissions, add generic flow rule
    high_findings = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    if high_findings and not forbidden_flows:
        forbidden_flows.append({"from": "internal_data", "to": ["email_external", "api_external"]})

    # Determine budget based on tool count and risk
    tool_count = len(all_tool_names)
    risk_multiplier = 0.5 if len(high_findings) > 3 else 1.0
    max_actions = int(max(20, tool_count * 10) * risk_multiplier)

    # Chain depth from delegation structure
    max_depth = 1
    for agent in arch.agents:
        if agent.delegates_to:
            max_depth = max(max_depth, len(agent.delegates_to) + 1)

    # Determine thresholds based on risk
    if len(high_findings) > 5:
        thresholds = {"warn": 0.2, "pause": 0.5, "kill": 0.7}
    elif len(high_findings) > 2:
        thresholds = {"warn": 0.3, "pause": 0.6, "kill": 0.8}
    else:
        thresholds = {"warn": 0.4, "pause": 0.7, "kill": 0.9}

    # Build the envelope
    envelope = {"name": f"{arch.name}-envelope"}

    if arch.agents:
        envelope["purpose"] = f"Behavioral envelope for {arch.agents[0].name}"

    if workflows:
        envelope["workflows"] = workflows

    envelope["bounds"] = {
        "max_actions_per_session": max_actions,
        "max_tokens_consumed": max_actions * 2000,
        "max_duration_seconds": max(60, max_actions * 6),
        "max_cost_usd": round(max_actions * 0.02, 2),
    }

    if forbidden_flows:
        envelope["bounds"]["data_flow"] = {"forbidden_flows": forbidden_flows}

    envelope["bounds"]["autonomy"] = {
        "max_chain_depth": max_depth,
    }

    # Add human approval requirements from auto-approved destructive tools
    approval_needed = []
    for agent in arch.agents:
        for tool in agent.tools:
            if tool.type in ("write", "execute") and tool.auto_approved:
                approval_needed.append(tool.name)
    if approval_needed:
        envelope["bounds"]["autonomy"]["requires_human_approval"] = approval_needed

    envelope["drift"] = {
        "unknown_workflow_threshold": 3 if high_findings else 5,
        "repetition": {
            "max_identical_calls": 3,
            "max_similar_calls": max(5, tool_count),
        },
    }

    envelope["responses"] = {
        "warn": {"threshold": thresholds["warn"]},
        "pause": {"threshold": thresholds["pause"]},
        "kill": {"threshold": thresholds["kill"]},
    }

    # Generate YAML with header
    header = (
        f"# Envelope generated by agentspec\n"
        f"# Source: {arch.name}\n"
        f"# Agents: {len(arch.agents)}, Tools: {tool_count}, "
        f"Findings: {len(findings)} ({len(high_findings)} high/critical)\n"
        f"# Edit thresholds and workflows to match your expected agent behavior.\n\n"
    )

    return header + yaml.dump(envelope, default_flow_style=False, sort_keys=False)


def _to_globs(tool_names: list[str]) -> list[str]:
    """Convert tool names to glob patterns for workflow matching.
    
    Groups tools with common prefixes into globs:
    ['read_file', 'read_db', 'read_account'] → ['read_*']
    ['send_email'] → ['send_email']
    """
    prefixes: dict[str, list[str]] = {}
    for name in tool_names:
        parts = name.split("_", 1)
        prefix = parts[0] if len(parts) > 1 else name
        prefixes.setdefault(prefix, []).append(name)

    globs = []
    for prefix, names in prefixes.items():
        if len(names) >= 2:
            globs.append(f"{prefix}_*")
        else:
            globs.append(names[0])
    return globs
