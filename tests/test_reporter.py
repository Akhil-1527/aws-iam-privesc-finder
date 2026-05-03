"""Tests for report rendering and CLI argument parsing."""
from __future__ import annotations

import json

from src.analyzer import analyze
from src.main import parse_args
from src.reporter import render_json, render_markdown


def test_render_markdown_includes_all_findings(make_policy_set, mock_policy):
    policy_set = make_policy_set(
        mock_policy("create_policy_version"),
        mock_policy("create_access_key"),
    )
    findings = analyze(policy_set)
    md = render_markdown(policy_set, findings)
    assert "AWS IAM Privesc Finder Report" in md
    assert "iam:CreatePolicyVersion" in md
    assert "iam:CreateAccessKey" in md
    assert "CRITICAL" in md
    assert policy_set.principal_arn in md


def test_render_markdown_no_findings_message(make_policy_set, mock_policy):
    policy_set = make_policy_set(mock_policy("safe_readonly"))
    findings = analyze(policy_set)
    md = render_markdown(policy_set, findings)
    assert "No privilege escalation paths were detected" in md


def test_render_json_is_valid_and_structured(make_policy_set, mock_policy):
    policy_set = make_policy_set(mock_policy("passrole_lambda"))
    findings = analyze(policy_set)
    payload = json.loads(render_json(policy_set, findings))
    assert payload["schema_version"] == "1.0"
    assert payload["target"]["arn"] == policy_set.principal_arn
    assert payload["summary"]["total"] == len(findings)
    assert any(
        f["technique_name"].startswith("iam:PassRole")
        for f in payload["findings"]
    )


def test_render_json_empty_findings(make_policy_set, mock_policy):
    policy_set = make_policy_set(mock_policy("safe_readonly"))
    payload = json.loads(render_json(policy_set, []))
    assert payload["summary"]["total"] == 0
    assert payload["findings"] == []


def test_cli_parse_user_target():
    args = parse_args(["--user", "alice", "--output", "json"])
    assert args.user == "alice"
    assert args.role_arn is None
    assert args.output == "json"


def test_cli_parse_role_target():
    args = parse_args(
        [
            "--role-arn",
            "arn:aws:iam::123:role/Foo",
            "--profile",
            "prod",
            "--verbose",
        ]
    )
    assert args.role_arn == "arn:aws:iam::123:role/Foo"
    assert args.profile == "prod"
    assert args.verbose is True


def test_cli_requires_target():
    """One of --user / --role-arn must be supplied (mutually exclusive, required)."""
    import pytest

    with pytest.raises(SystemExit):
        parse_args([])
