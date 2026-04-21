"""Parse OpenAI Agents SDK Python files into Architecture model.

Extracts Agent() definitions, @function_tool decorators, .as_tool() calls,
and handoff patterns from Python source via regex (no AST import needed).
"""

from __future__ import annotations
import re
from ..model import Architecture, Agent, Tool


def parse(path: str) -> Architecture:
    with open(path) as f:
        source = f.read()

    agents = _extract_agents(source)
    if not agents:
        agents = [Agent(name="main", tools=_extract_function_tools(source))]

    return Architecture(name=_infer_name(path), agents=agents)


def _extract_agents(source: str) -> list[Agent]:
    agents: list[Agent] = []
    func_tools = _extract_function_tools(source)
    func_tool_names = {t.name for t in func_tools}

    # Match: var = Agent(name="...", ...)
    for m in re.finditer(
        r'(\w+)\s*=\s*Agent\(\s*name\s*=\s*["\']([^"\']+)["\']', source
    ):
        var_name, agent_name = m.group(1), m.group(2)
        # Extract the full Agent(...) block
        start = m.start()
        block = _extract_parens(source, source.index("(", start))

        tools = _extract_tools_from_block(block, func_tool_names)
        handoffs = _extract_handoffs(block, source)
        delegates = _extract_as_tool_delegates(block, source)

        agent = Agent(
            name=agent_name,
            tools=tools,
            delegates_to=handoffs + delegates,
            system_prompt=_extract_string_field(block, "instructions"),
        )
        agents.append(agent)

    return agents


def _extract_function_tools(source: str) -> list[Tool]:
    tools = []
    for m in re.finditer(r'@function_tool\s+(?:async\s+)?def\s+(\w+)', source):
        tools.append(Tool(name=m.group(1), type=_infer_type(m.group(1)), auto_approved=True))
    return tools


def _extract_tools_from_block(block: str, func_tool_names: set[str]) -> list[Tool]:
    tools = []
    # tools=[get_weather, search_web] or tools=[spanish_agent.as_tool(...)]
    tools_match = re.search(r'tools\s*=\s*\[([^\]]*)\]', block, re.DOTALL)
    if not tools_match:
        return tools

    tools_str = tools_match.group(1)

    # .as_tool() references
    for m in re.finditer(r'(\w+)\.as_tool\(', tools_str):
        tools.append(Tool(name=m.group(1), type="external", auto_approved=True))

    # Direct function references
    for m in re.finditer(r'\b(\w+)\b', tools_str):
        name = m.group(1)
        if name in func_tool_names:
            tools.append(Tool(name=name, type=_infer_type(name), auto_approved=True))

    # WebSearchTool, FileSearchTool, CodeInterpreterTool, ComputerTool
    for m in re.finditer(r'(WebSearchTool|FileSearchTool|CodeInterpreterTool|ComputerTool)', tools_str):
        tmap = {
            "WebSearchTool": ("web_search", "external"),
            "FileSearchTool": ("file_search", "read"),
            "CodeInterpreterTool": ("code_interpreter", "execute"),
            "ComputerTool": ("computer_use", "execute"),
        }
        name, ttype = tmap.get(m.group(1), (m.group(1), "read"))
        tools.append(Tool(name=name, type=ttype, auto_approved=True))

    return tools


def _extract_handoffs(block: str, source: str) -> list[str]:
    names = []
    for m in re.finditer(r'handoffs\s*=\s*\[([^\]]*)\]', block, re.DOTALL):
        for ref in re.finditer(r'\b(\w+)\b', m.group(1)):
            name = ref.group(1)
            if re.search(rf'{name}\s*=\s*Agent\(', source):
                names.append(name)
    return names


def _extract_as_tool_delegates(block: str, source: str) -> list[str]:
    names = []
    for m in re.finditer(r'(\w+)\.as_tool\(', block):
        var = m.group(1)
        agent_match = re.search(rf'{var}\s*=\s*Agent\(\s*name\s*=\s*["\']([^"\']+)', source)
        if agent_match:
            names.append(agent_match.group(1))
    return names


def _extract_string_field(block: str, field: str) -> str:
    m = re.search(rf'{field}\s*=\s*["\']([^"\']*)["\']', block)
    if m:
        return m.group(1)
    m = re.search(rf'{field}\s*=\s*\(\s*["\']([^"\']*)["\']', block)
    return m.group(1) if m else ""


def _extract_parens(source: str, start: int) -> str:
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    return source[start:]


def _infer_name(path: str) -> str:
    import os
    return os.path.splitext(os.path.basename(path))[0]


def _infer_type(name: str) -> str:
    nl = name.lower()
    if any(k in nl for k in ("exec", "bash", "shell", "run", "command", "interpret")):
        return "execute"
    if any(k in nl for k in ("write", "create", "delete", "edit", "send", "post")):
        return "write"
    if any(k in nl for k in ("search", "web", "fetch", "http", "browse", "scrape")):
        return "external"
    return "read"
