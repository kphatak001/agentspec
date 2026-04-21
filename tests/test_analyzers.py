"""Tests for agentspec analyzers, parser, and scorer."""

import json
import os
import tempfile
import unittest

from agentspec.model import Architecture, Agent, Tool, MemorySource, Finding
from agentspec.analyzer import run
from agentspec.scorer import score
from agentspec import parser


# ── Helpers ──────────────────────────────────────────────


def _arch(**kwargs) -> Architecture:
    defaults = dict(name="test", agents=[], memory_sources=[], logging={}, human_in_the_loop={})
    defaults.update(kwargs)
    return Architecture(**defaults)


def _agent(name="main", tools=None, **kw) -> Agent:
    return Agent(name=name, tools=tools or [], **kw)


def _tool(name="t", type="read", scope="*", auto_approved=False, **kw) -> Tool:
    return Tool(name=name, type=type, scope=scope, auto_approved=auto_approved, **kw)


# ── Analyzer Tests ───────────────────────────────────────


class TestPromptInjection(unittest.TestCase):
    def test_external_plus_write_is_critical(self):
        arch = _arch(agents=[_agent(tools=[
            _tool("web_search", type="external"),
            _tool("fs_write", type="write"),
        ])])
        findings = run(arch)
        crit = [f for f in findings if f.owasp_id == "OWASP-AGENT-01" and f.severity == "CRITICAL"]
        self.assertTrue(len(crit) >= 1)

    def test_external_only_is_medium(self):
        arch = _arch(agents=[_agent(tools=[_tool("web_search", type="external")])])
        findings = run(arch)
        medium = [f for f in findings if f.owasp_id == "OWASP-AGENT-01" and f.severity == "MEDIUM"]
        self.assertTrue(len(medium) >= 1)

    def test_no_external_no_finding(self):
        arch = _arch(agents=[_agent(tools=[_tool("fs_read", type="read")])])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-01"]
        self.assertEqual(len(findings), 0)

    def test_unvalidated_rag_with_write(self):
        arch = _arch(
            agents=[_agent(tools=[_tool("bash", type="execute")])],
            memory_sources=[MemorySource(name="wiki", type="external", content_validated=False)],
        )
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-01" and f.severity == "HIGH"]
        self.assertTrue(len(findings) >= 1)


class TestUnsafeToolExec(unittest.TestCase):
    def test_unrestricted_execute_is_critical(self):
        arch = _arch(agents=[_agent(tools=[_tool("bash", type="execute", scope="*")])])
        crit = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-02" and f.severity == "CRITICAL"]
        self.assertTrue(len(crit) >= 1)

    def test_unrestricted_write_is_critical(self):
        arch = _arch(agents=[_agent(tools=[_tool("fs_write", type="write", scope="*")])])
        crit = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-02" and f.severity == "CRITICAL"]
        self.assertTrue(len(crit) >= 1)

    def test_scoped_write_is_low(self):
        arch = _arch(agents=[_agent(tools=[_tool("fs_write", type="write", scope="src/**")])])
        low = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-02" and f.severity == "LOW"]
        self.assertTrue(len(low) >= 1)

    def test_read_only_no_finding(self):
        arch = _arch(agents=[_agent(tools=[_tool("grep", type="read")])])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-02"]
        self.assertEqual(len(findings), 0)


class TestExcessivePermissions(unittest.TestCase):
    def test_auto_approved_write_is_critical(self):
        arch = _arch(agents=[_agent(tools=[_tool("bash", type="execute", auto_approved=True)])])
        crit = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-03" and f.severity == "CRITICAL"]
        self.assertTrue(len(crit) >= 1)

    def test_read_only_auto_approved_no_critical(self):
        arch = _arch(agents=[_agent(tools=[_tool("grep", type="read", auto_approved=True)])])
        crit = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-03" and f.severity == "CRITICAL"]
        self.assertEqual(len(crit), 0)


class TestOutputValidation(unittest.TestCase):
    def test_delegation_without_validation(self):
        arch = _arch(agents=[
            _agent("parent", delegates_to=["child"], output_validated=False),
            _agent("child"),
        ])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-04"]
        self.assertTrue(len(findings) >= 1)

    def test_no_delegation_no_finding(self):
        arch = _arch(agents=[_agent("solo")])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-04"]
        self.assertEqual(len(findings), 0)


class TestSandboxing(unittest.TestCase):
    def test_exec_without_sandbox(self):
        arch = _arch(agents=[_agent(tools=[_tool("bash", type="execute")])])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-05" and f.severity == "HIGH"]
        self.assertTrue(len(findings) >= 1)


class TestAgentTrust(unittest.TestCase):
    def test_unvalidated_delegation(self):
        arch = _arch(agents=[
            _agent("parent", delegates_to=["child"], output_validated=False),
            _agent("child"),
        ])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-06"]
        self.assertTrue(len(findings) >= 1)

    def test_single_agent_no_finding(self):
        arch = _arch(agents=[_agent("solo")])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-06"]
        self.assertEqual(len(findings), 0)


class TestInsecureMemory(unittest.TestCase):
    def test_unvalidated_external_rag(self):
        arch = _arch(
            agents=[_agent(tools=[_tool("bash", type="execute")])],
            memory_sources=[MemorySource(name="wiki", type="external", content_validated=False)],
        )
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-07"]
        self.assertTrue(len(findings) >= 1)

    def test_writable_memory(self):
        arch = _arch(
            memory_sources=[MemorySource(name="db", type="database", writable=True)],
        )
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-07"]
        self.assertTrue(len(findings) >= 1)

    def test_no_memory_no_finding(self):
        arch = _arch()
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-07"]
        self.assertEqual(len(findings), 0)


class TestUncontrolledAutonomy(unittest.TestCase):
    def test_hitl_gaps(self):
        arch = _arch(
            agents=[_agent(tools=[_tool("bash", type="execute")])],
            human_in_the_loop={"destructive_actions": True, "external_calls": False},
        )
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-08"]
        self.assertTrue(len(findings) >= 1)


class TestLogging(unittest.TestCase):
    def test_no_logging_config(self):
        arch = _arch()
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-09"]
        self.assertTrue(len(findings) >= 1)

    def test_full_logging_no_finding(self):
        arch = _arch(logging={"tool_calls": True, "agent_decisions": True, "output_content": True})
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-09"]
        self.assertEqual(len(findings), 0)


class TestAgentCommunication(unittest.TestCase):
    def test_remote_mcp(self):
        arch = _arch(agents=[_agent(tools=[
            _tool("deploy", type="external", mcp_server="cloud-mcp"),
        ])])
        findings = [f for f in run(arch) if f.owasp_id == "OWASP-AGENT-10"]
        self.assertTrue(len(findings) >= 1)


# ── Scorer Tests ─────────────────────────────────────────


class TestScorer(unittest.TestCase):
    def test_no_findings_is_low(self):
        tm = score(_arch(), [])
        self.assertEqual(tm.overall_rating, "LOW")
        self.assertEqual(tm.overall_score, 0.0)

    def test_critical_findings_score_high(self):
        findings = [Finding(
            owasp_id="OWASP-AGENT-02", owasp_name="Unsafe Tool Execution",
            severity="CRITICAL", title="test", description="test",
            attack_scenario="test", affected="test", mitigation="test", score=95.0,
        )]
        tm = score(_arch(), findings)
        self.assertGreaterEqual(tm.overall_score, 70)
        self.assertEqual(tm.overall_rating, "CRITICAL")

    def test_weighted_average_uses_top_5(self):
        findings = [
            Finding("A", "A", "CRITICAL", "t", "t", "t", "t", "t", score=100.0),
            Finding("B", "B", "HIGH", "t", "t", "t", "t", "t", score=60.0),
            Finding("C", "C", "MEDIUM", "t", "t", "t", "t", "t", score=40.0),
            Finding("D", "D", "LOW", "t", "t", "t", "t", "t", score=20.0),
            Finding("E", "E", "LOW", "t", "t", "t", "t", "t", score=10.0),
            Finding("F", "F", "INFO", "t", "t", "t", "t", "t", score=5.0),  # ignored
        ]
        tm = score(_arch(), findings)
        # top 5 by score: 100, 60, 40, 20, 10
        # (100*5 + 60*4 + 40*3 + 20*2 + 10*1) / 15 = 60.67
        self.assertAlmostEqual(tm.overall_score, 60.7, places=1)


# ── Filter Tests ─────────────────────────────────────────


class TestFilters(unittest.TestCase):
    def test_owasp_filter(self):
        arch = _arch(agents=[_agent(tools=[
            _tool("bash", type="execute", auto_approved=True),
            _tool("web", type="external"),
        ])])
        findings = run(arch, owasp_filter={"02"})
        for f in findings:
            self.assertEqual(f.owasp_id, "OWASP-AGENT-02")

    def test_severity_filter(self):
        arch = _arch(agents=[_agent(tools=[
            _tool("bash", type="execute", scope="*"),
            _tool("fs_write", type="write", scope="src/**"),
        ])])
        findings = run(arch, min_severity="HIGH")
        for f in findings:
            self.assertIn(f.severity, ("CRITICAL", "HIGH"))


# ── Parser Tests ─────────────────────────────────────────


class TestParser(unittest.TestCase):
    def test_agentspec_yaml(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "code-assistant.yaml")
        if os.path.exists(path):
            arch = parser.parse(path)
            self.assertEqual(arch.name, "code-assistant")
            self.assertEqual(len(arch.agents), 2)

    def test_claude_code_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"permissions": {"allow": ["Bash", "Read"], "deny": ["Edit(~/.ssh/**)"]}}, f)
            f.flush()
            arch = parser.parse(f.name)
            self.assertEqual(arch.name, "claude-code")
            self.assertTrue(len(arch.agents[0].tools) >= 2)
        os.unlink(f.name)

    def test_openai_agents_py(self):
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "openai-devops-agent.py")
        if os.path.exists(path):
            arch = parser.parse(path)
            self.assertTrue(len(arch.agents) >= 2)
            names = {a.name for a in arch.agents}
            self.assertIn("devops_orchestrator", names)


# ── Safe Config Test ─────────────────────────────────────


class TestSafeConfig(unittest.TestCase):
    def test_chatbot_is_clean(self):
        arch = _arch(
            agents=[_agent("chatbot", tools=[])],
            logging={"tool_calls": True, "agent_decisions": True, "output_content": True},
        )
        findings = run(arch)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
