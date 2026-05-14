# agentspec

Threat model generator for agentic AI systems. OWASP Top 10 for Agentic AI — mapped, scored, actionable.

Describe your agent architecture. Get a threat model.

```
$ agentspec model agent.yaml -v

agentspec threat model
═══════════════════════════════════════════════════════

  Architecture: 2 agents, 2 MCP servers, 10 tools, 2 RAG sources
  Risk Score: 87/100 (CRITICAL)

  #1 🔴 CRITICAL — Prompt Injection (OWASP-AGENT-01)
  │ Indirect prompt injection via external content + write/execute tools
  │ Attack: Attacker places injection payload on web page. Agent fetches it,
  │         follows injected instructions, executes malicious commands.
  │ Fix: Sanitize external content. Separate fetching from action-taking.
  │
  #2 🔴 CRITICAL — Unsafe Tool Execution (OWASP-AGENT-02)
  │ Unrestricted command execution via 'execute_bash'
  │ Attack: Prompt injection → arbitrary command execution → data exfiltration
  │ Fix: Add allowedCommands whitelist or sandbox with nsjail
  ...
```

## Install

```bash
pip install agentspec
```

Or from source:

```bash
git clone https://github.com/kphatak001/agentspec
cd agentspec
pip install -e .
```

## Usage

```bash
# Native agentspec YAML
agentspec model agent.yaml

# Claude Code settings
agentspec model ~/.claude/settings.json

# OpenAI Agents SDK Python
agentspec model my_agents.py

# Kiro CLI agent config
agentspec model ~/.kiro/agents/my-agent.json

# CrewAI crew definition
agentspec model crew.yaml --format crewai

# Output options
agentspec model agent.yaml -v                          # verbose attack scenarios
agentspec model agent.yaml --output-format markdown -o report.md
agentspec model agent.yaml --output-format json -o report.json

# Filters
agentspec model agent.yaml --min-severity HIGH         # only HIGH and CRITICAL
agentspec model agent.yaml --owasp 01,02,03            # specific categories
```

## Supported Formats

| Format | Auto-detected | Flag |
|--------|--------------|------|
| agentspec YAML | `.yaml` with agent structure | `--format agentspec` |
| Claude Code | `.json` with `permissions` key | `--format claude-code` |
| OpenAI Agents SDK | `.py` with `Agent()` definitions | `--format openai-agents` |
| Kiro CLI | `.json` with `allowedTools`/`mcpServers` | `--format kiro` |
| CrewAI | `.yaml` with `role`/`backstory` | `--format crewai` |

## OWASP Coverage

### OWASP Top 10 for Agentic AI (2025)

| # | Category | What agentspec checks |
|---|----------|----------------------|
| 01 | Prompt Injection | External content + write/execute tools, unvalidated RAG |
| 02 | Unsafe Tool Execution | Unrestricted execute/write scope |
| 03 | Excessive Permissions | Auto-approved destructive tools, broad MCP servers |
| 04 | Insufficient Output Validation | Delegation without output checks |
| 05 | Inadequate Sandboxing | No container/sandbox for execution tools |
| 06 | Implicit Trust Between Agents | Unvalidated subagent output, privilege escalation |
| 07 | Insecure Memory/RAG | Unvalidated external sources, writable memory |
| 08 | Uncontrolled Autonomy | HITL gaps, auto-approved destructive tools |
| 09 | Inadequate Logging | Disabled or missing logging fields |
| 10 | Insecure Agent Communication | Remote MCP without TLS |

### OWASP Agentic Skills Top 10 — AST10 (2026)

| # | Risk | What agentspec checks |
|---|------|----------------------|
| AST01 | Malicious Skills | Cross-ref from prompt injection + insecure memory findings |
| AST02 | Supply Chain Compromise | Remote MCP servers without provenance verification |
| AST03 | Over-Privileged Skills | Cross-ref from excessive permissions findings |
| AST04 | Insecure Metadata | Cross-ref from output validation findings |
| AST05 | Unsafe Deserialization | Cross-ref from insecure memory findings |
| AST06 | Weak Isolation | Cross-ref from sandboxing + agent communication findings |
| AST07 | Update Drift | @latest MCP servers without version pinning |
| AST08 | Poor Scanning | No skill scanning or validation configured |
| AST09 | No Governance | Cross-ref from autonomy + logging findings |
| AST10 | Cross-Platform Reuse | Cross-ref from agent trust + communication findings |

All findings include AST10 cross-references where applicable.

## Design Principles

1. **Static analysis only.** No API calls, no runtime, no cost.
2. **OWASP-mapped.** Every finding cites a specific OWASP category.
3. **Actionable mitigations.** Every finding says what to change in the config.
4. **Format-agnostic.** Parsers are pluggable. Works with any agent framework.
5. **Partial analysis is fine.** Missing info → skip that analyzer, don't fail.

## CI / GitHub Action

Add agentspec to your CI pipeline — it comments findings directly on PRs:

```yaml
# .github/workflows/agentspec.yml
name: Agent Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: kphatak001/agentspec@main
        with:
          config: agent.yaml        # your agent config
          fail-on: HIGH             # fail PR if HIGH or CRITICAL findings
          emit-policy: mcpfw        # optionally generate a policy file
```

Inputs: `config`, `format`, `min-severity`, `fail-on` (CRITICAL/HIGH/MEDIUM/LOW/none), `emit-policy` (mcpfw/rego/cedar/agt).

## Generate Runtime Policies

agentspec generates enforcement policies for multiple runtimes directly from its findings:

```bash
# mcpfw (default) — transparent MCP proxy
agentspec model agent.yaml --emit-policy -o policy.yaml

# OPA Rego — for OPA/Gatekeeper/Styra
agentspec model agent.yaml --emit-policy --policy-format rego -o policy.rego

# Cedar — for AWS Verified Permissions / Cedar
agentspec model agent.yaml --emit-policy --policy-format cedar -o policy.cedar

# Microsoft Agent Governance Toolkit
agentspec model agent.yaml --emit-policy --policy-format agt -o policy.yaml
```

Static analysis finds the risks. Your runtime enforces them — whichever runtime you use.

## Generate Behavioral Envelopes

agentspec generates [agent-envelope](https://github.com/kphatak001/agent-envelope) YAML for session-level behavioral enforcement:

```bash
agentspec model agent.yaml --emit-envelope -o envelope.yaml
```

The generated envelope includes:
- **Workflow patterns** derived from your agent's tool types (read → process → write)
- **Budget limits** scaled to tool count and risk level
- **Forbidden data flows** based on sensitive reads + external writes
- **Drift thresholds** tightened automatically for high-risk architectures

Use with mcpfw's HTTP proxy mode for network-enforced session policy:

```bash
# Generate both layers from one scan
agentspec model agent.yaml --emit-policy -o policy.yaml
agentspec model agent.yaml --emit-envelope -o envelope.yaml

# Enforce at the network layer
mcpfw --listen :8443 --target https://mcp-server:3000 \
      --policy policy.yaml --envelope envelope.yaml
```

This closes the governance loop: **scan → generate → enforce**. No manual policy authoring required.

## The Trilogy

agentspec is part of a three-layer open-source agent security stack:

| Layer | Tool | Question | Timing |
|-------|------|----------|--------|
| Pre-deploy | **agentspec** | "Is this agent config risky?" | Before launch |
| Runtime (session) | [agent-envelope](https://github.com/kphatak001/agent-envelope) | "Is this agent off-script?" | Continuous |
| Runtime (per-call) | [mcpfw](https://github.com/kphatak001/mcpfw) | "Is this specific call allowed?" | Each action |

agentspec generates policies for both runtime layers automatically.

## Dependencies

- Python 3.10+
- pyyaml
- rich (optional, for colored output)

## License

Apache-2.0 — see [LICENSE](LICENSE).
