"""CLI entrypoint for aws-iam-privesc-finder.

Examples:
    aws-privesc-finder --user alice --output both
    aws-privesc-finder --profile staging --role-arn arn:aws:iam::1234:role/Dev
    aws-privesc-finder --user bob --output json > findings.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from .analyzer import analyze
from .enumerator import IAMEnumerator
from .reporter import print_console_summary, render_json, render_markdown
from .utils import build_session, configure_logging, get_logger


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="aws-privesc-finder",
        description=(
            "Identify IAM privilege escalation paths for a target user or role. "
            "For authorized security assessments only."
        ),
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name from ~/.aws/credentials. Defaults to environment.",
    )
    parser.add_argument(
        "--region",
        help="Optional AWS region override (most IAM ops are region-agnostic).",
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--user", help="IAM user name to analyze.")
    target.add_argument(
        "--role-arn",
        dest="role_arn",
        help="Full IAM role ARN (or role name) to analyze.",
    )

    parser.add_argument(
        "--output",
        choices=("markdown", "json", "both", "console"),
        default="console",
        help="Output format. 'console' prints rich-formatted summary only. "
        "'markdown'/'json'/'both' write report files.",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for written report files (default: current directory).",
    )
    parser.add_argument(
        "--report-name",
        default="privesc-report",
        help="Base filename (without extension) for written reports.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    parser.add_argument(
        "--no-console",
        action="store_true",
        help="Suppress the Rich console summary.",
    )
    return parser.parse_args(argv)


def write_outputs(
    args: argparse.Namespace,
    md_text: str | None,
    json_text: str | None,
    console: Console,
) -> list[Path]:
    """Write report files according to ``args.output`` and return paths written."""
    outputs: list[Path] = []
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if md_text is not None:
        md_path = output_dir / f"{args.report_name}.md"
        md_path.write_text(md_text, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {md_path}")
        outputs.append(md_path)

    if json_text is not None:
        json_path = output_dir / f"{args.report_name}.json"
        json_path.write_text(json_text, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {json_path}")
        outputs.append(json_path)

    return outputs


def run(args: argparse.Namespace, console: Console | None = None) -> int:
    """Run the CLI logic. Returns a process exit code (0=ok, 1=error, 2=findings).

    Exit code 2 is returned when at least one finding is detected, so the tool
    can be used as a gate in CI pipelines.
    """
    console = console or Console()
    logger = configure_logging(verbose=args.verbose)

    session = build_session(profile=args.profile, region=args.region)
    enumerator = IAMEnumerator(session)

    try:
        if args.user:
            policy_set = enumerator.enumerate_user(args.user)
        else:
            policy_set = enumerator.enumerate_role(args.role_arn)
    except Exception as exc:  # noqa: BLE001 — surface AWS errors cleanly
        logger.error("Enumeration failed: %s", exc)
        return 1

    findings = analyze(policy_set)

    if not args.no_console:
        print_console_summary(policy_set, findings, console=console)

    md_text: str | None = None
    json_text: str | None = None
    if args.output in {"markdown", "both"}:
        md_text = render_markdown(policy_set, findings)
    if args.output in {"json", "both"}:
        json_text = render_json(policy_set, findings)

    write_outputs(args, md_text, json_text, console)

    return 2 if findings else 0


def main(argv: list[str] | None = None) -> int:
    """Module entry point used by ``console_scripts``."""
    args = parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
