"""CLI entry point for agentspec."""

from __future__ import annotations
import argparse
import sys
from . import parser, analyzer, scorer, reporter


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentspec", description="Threat model generator for agentic AI systems")
    sub = ap.add_subparsers(dest="command")

    model_p = sub.add_parser("model", help="Generate threat model from agent config")
    model_p.add_argument("config", help="Path to agent config file")
    model_p.add_argument("--format", dest="fmt", default="auto",
                        choices=["auto", "agentspec", "kiro", "crewai", "claude-code", "openai-agents"])
    model_p.add_argument("--output-format", default="terminal", choices=["terminal", "json", "markdown"])
    model_p.add_argument("-o", "--output", help="Write report to file")
    model_p.add_argument("--min-severity", default="INFO", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    model_p.add_argument("--owasp", default="all", help="Filter OWASP categories: 01,02,03 or all")
    model_p.add_argument("-v", "--verbose", action="store_true")

    args = ap.parse_args(argv)
    if args.command != "model":
        ap.print_help()
        return 1

    try:
        arch = parser.parse(args.config, args.fmt)
    except Exception as e:
        print(f"Error parsing {args.config}: {e}", file=sys.stderr)
        return 1

    owasp_filter = None if args.owasp == "all" else set(args.owasp.split(","))
    findings = analyzer.run(arch, owasp_filter=owasp_filter, min_severity=args.min_severity)
    tm = scorer.score(arch, findings)

    if args.output_format == "json":
        out = reporter.to_json(tm)
    elif args.output_format == "markdown":
        out = reporter.to_markdown(tm)
    else:
        out = reporter.terminal(tm, verbose=args.verbose)

    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"Report written to {args.output}")
    else:
        print(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
