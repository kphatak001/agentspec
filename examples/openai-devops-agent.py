"""
OpenAI Agents SDK example: DevOps agent with tools and handoffs.
"""

from agents import Agent, Runner, function_tool


@function_tool
def execute_shell(command: str) -> str:
    """Execute a shell command on the server."""
    return f"Executed: {command}"


@function_tool
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    return f"Contents of {path}"


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    return f"Wrote to {path}"


@function_tool
def web_search(query: str) -> str:
    """Search the web for information."""
    return f"Results for: {query}"


@function_tool
def deploy_service(service: str, env: str) -> str:
    """Deploy a service to an environment."""
    return f"Deployed {service} to {env}"


@function_tool
def query_database(sql: str) -> str:
    """Run a SQL query against the production database."""
    return f"Query result: {sql}"


code_reviewer = Agent(
    name="code_reviewer",
    instructions="You review code changes for quality and security issues.",
    tools=[read_file],
)

security_scanner = Agent(
    name="security_scanner",
    instructions="You scan code and infrastructure for security vulnerabilities.",
    tools=[read_file, execute_shell],
)

orchestrator = Agent(
    name="devops_orchestrator",
    instructions=(
        "You are a DevOps automation agent. You deploy services, "
        "manage infrastructure, and coordinate code reviews."
    ),
    tools=[
        execute_shell,
        read_file,
        write_file,
        web_search,
        deploy_service,
        query_database,
        code_reviewer.as_tool(
            tool_name="review_code",
            tool_description="Get a code review from the code reviewer",
        ),
        security_scanner.as_tool(
            tool_name="scan_security",
            tool_description="Run a security scan",
        ),
    ],
    handoffs=[code_reviewer, security_scanner],
)
