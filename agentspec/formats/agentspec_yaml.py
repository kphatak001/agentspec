"""Parse native agentspec YAML format into Architecture model."""

from __future__ import annotations
import yaml
from ..model import Architecture, Agent, Tool, MemorySource


def parse(path: str) -> Architecture:
    with open(path) as f:
        data = yaml.safe_load(f)

    agents = []
    auto_approved_set: set[str] = set()

    for ad in data.get("agents", []):
        auto_approved_set = set(ad.get("auto_approved", []))
        tools = []
        for td in ad.get("tools", []):
            tools.append(Tool(
                name=td["name"],
                type=td.get("type", "read"),
                scope=td.get("scope", "*"),
                auto_approved=td["name"] in auto_approved_set,
            ))
        for mcp in ad.get("mcp_servers", []):
            for tn in mcp.get("tools", []):
                tools.append(Tool(
                    name=tn,
                    type="external",
                    scope="*",
                    auto_approved=tn in auto_approved_set,
                    mcp_server=mcp["name"],
                ))
        delegates = [d["name"] for d in ad.get("delegates_to", [])]
        agents.append(Agent(
            name=ad["name"],
            model=ad.get("model", ""),
            tools=tools,
            delegates_to=delegates,
            output_validated=all(
                d.get("output_validated", False)
                for d in ad.get("delegates_to", [{}])
            ) if ad.get("delegates_to") else True,
            system_prompt=ad.get("system_prompt", ""),
        ))

    mem = data.get("memory", {})
    sources = []
    for s in mem.get("sources", []):
        sources.append(MemorySource(
            name=s["name"],
            type=s.get("type", "local_files"),
            writable=s.get("writable", False),
            content_validated=s.get("content_validated", False),
        ))

    return Architecture(
        name=data.get("name", "unnamed"),
        agents=agents,
        memory_sources=sources,
        logging=data.get("logging", {}),
        human_in_the_loop=data.get("human_in_the_loop", {}),
    )
