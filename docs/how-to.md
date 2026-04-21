# How to Use agentspec

## Quick Start

```bash
# Analyze an agent config
agentspec model agent.yaml

# With verbose attack scenarios
agentspec model agent.yaml -v

# Output as markdown report
agentspec model agent.yaml --output-format markdown -o threat-model.md

# Output as JSON
agentspec model agent.yaml --output-format json -o threat-model.json
```

## Writing Your Agent YAML

Describe your agent architecture in the native agentspec format:

```yaml
name: my-agent
description: What this agent does

agents:
  - name: main
    model: claude-sonnet
    system_prompt: "You are a helpful assistant..."

    tools:
      - name: fs_read
        type: read           # read, write, execute, external
        scope: "project/**"  # path glob, "*" for unrestricted
      - name: fs_write
        type: write
        scope: "project/**"
      - name: execute_bash
        type: execute
        scope: "*"

    # Tools that don't require human approval
    auto_approved:
      - fs_read

    # MCP servers this agent connects to
    mcp_servers:
      - name: git-mcp
        tools: [git_status, git_commit]

    # Sub-agents this agent delegates to
    delegates_to:
      - name: reviewer
        output_validated: false  # ← this will flag OWASP-AGENT-04/06

  - name: reviewer
    model: claude-haiku
    tools:
      - name: fs_read
        type: read

# RAG / memory sources
memory:
  sources:
    - name: docs
      type: local_files       # local_files, external, database
      writable: false
      content_validated: true
    - name: wiki
      type: external
      content_validated: false # ← this will flag OWASP-AGENT-07

# What gets logged
logging:
  tool_calls: true
  agent_decisions: true
  output_content: true

# What requires human approval
human_in_the_loop:
  destructive_actions: true
  external_calls: true
  delegation: true
```

### Tool Types

| Type | Meaning | Examples |
|------|---------|---------|
| `read` | Reads data, no side effects | fs_read, code_search, grep |
| `write` | Modifies files or state | fs_write, create_file, db_insert |
| `execute` | Runs arbitrary commands | execute_bash, shell, kubectl |
| `external` | Fetches from outside sources | web_search, url_fetch, API calls |

### Scope

- `"project/**"` — restricted to project directory
- `"*"` — unrestricted (will flag findings)
- Any glob pattern — analyzed for breadth

## Using Existing Configs

agentspec auto-detects format from file content:

```bash
# Kiro CLI agent config (JSON with allowedTools/mcpServers)
agentspec model ~/.kiro/agents/my-agent.json

# CrewAI crew definition (YAML with role/backstory)
agentspec model crew.yaml --format crewai

# Force a specific format
agentspec model config.yaml --format agentspec
```

Not every format captures everything. agentspec will tell you what it can't assess:

```
⚠ No memory/RAG configuration found (can't assess OWASP-AGENT-07)
⚠ No delegation topology found (can't assess OWASP-AGENT-06)
Proceeding with partial analysis...
```

## Filtering Results

```bash
# Only CRITICAL and HIGH findings
agentspec model agent.yaml --min-severity HIGH

# Only specific OWASP categories
agentspec model agent.yaml --owasp 01,02,03

# Combine filters
agentspec model agent.yaml --min-severity MEDIUM --owasp 01,02 -v
```

## OWASP Categories

| ID | Name | What It Checks |
|----|------|---------------|
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

## Scoring

Each finding gets a score (0–100). Overall score is the weighted average of the top 5:

| Score | Rating |
|-------|--------|
| ≥ 70 | CRITICAL |
| ≥ 50 | HIGH |
| ≥ 30 | MEDIUM |
| < 30 | LOW |

## Example Outputs

A safe chatbot with no tools:
```
Risk Score: 0/100 (LOW)
```

A typical coding assistant:
```
Risk Score: 87/100 (CRITICAL)
11 findings across 8 OWASP categories
```

A fully autonomous DevOps agent:
```
Risk Score: 95/100 (CRITICAL)
17 findings — every category flagged
```
