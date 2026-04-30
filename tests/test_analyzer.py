"""Tests for the privesc detection rules.

Each technique gets a positive and a negative case. The negative is the
``safe_readonly`` policy so it covers every check at once.
"""
from __future__ import annotations

import pytest

from src.analyzer import (
    ALL_CHECKS,
    RiskLevel,
    analyze,
    check_add_user_to_group,
    check_assume_role_chain,
    check_attach_role_policy,
    check_attach_user_policy,
    check_create_access_key,
    check_create_login_profile,
    check_create_policy_version,
    check_passrole_cloudformation,
    check_passrole_codebuild,
    check_passrole_ec2,
    check_passrole_glue,
    check_passrole_lambda,
    check_put_user_policy,
    check_set_default_policy_version,
    check_update_assume_role_policy,
    check_update_login_profile,
)


# -------------------------------------------------------------------- #
# Negative case: read-only never triggers anything                     #
# -------------------------------------------------------------------- #


def test_safe_readonly_yields_no_findings(mock_policy, make_policy_set):
    policy_set = make_policy_set(mock_policy("safe_readonly"))
    findings = analyze(policy_set)
    assert findings == []


# -------------------------------------------------------------------- #
# Positive cases — one parametrized test per technique                 #
# -------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "policy_name,check_fn,expected_risk",
    [
        ("create_policy_version", check_create_policy_version, RiskLevel.CRITICAL),
        (
            "set_default_policy_version",
            check_set_default_policy_version,
            RiskLevel.HIGH,
        ),
        ("passrole_ec2", check_passrole_ec2, RiskLevel.CRITICAL),
        ("passrole_lambda", check_passrole_lambda, RiskLevel.CRITICAL),
        ("passrole_glue", check_passrole_glue, RiskLevel.HIGH),
        ("create_access_key", check_create_access_key, RiskLevel.CRITICAL),
        ("create_login_profile", check_create_login_profile, RiskLevel.CRITICAL),
        ("update_login_profile", check_update_login_profile, RiskLevel.CRITICAL),
        ("attach_user_policy", check_attach_user_policy, RiskLevel.CRITICAL),
        ("attach_role_policy", check_attach_role_policy, RiskLevel.CRITICAL),
        ("put_user_policy", check_put_user_policy, RiskLevel.CRITICAL),
        ("add_user_to_group", check_add_user_to_group, RiskLevel.CRITICAL),
        (
            "update_assume_role_policy",
            check_update_assume_role_policy,
            RiskLevel.CRITICAL,
        ),
        (
            "passrole_cloudformation",
            check_passrole_cloudformation,
            RiskLevel.HIGH,
        ),
        ("passrole_codebuild", check_passrole_codebuild, RiskLevel.HIGH),
    ],
)
def test_individual_checks_detect_their_technique(
    mock_policy, make_policy_set, policy_name, check_fn, expected_risk
):
    policy_set = make_policy_set(mock_policy(policy_name))
    finding = check_fn(policy_set)
    assert finding is not None, f"{check_fn.__name__} should fire on {policy_name}"
    assert finding.risk_level == expected_risk
    assert finding.matched_permissions
    assert finding.required_permissions
    assert finding.mitre_attack_ref


def test_assume_role_chain_wildcard(mock_policy, make_policy_set):
    policy_set = make_policy_set(mock_policy("assume_role_wildcard"))
    finding = check_assume_role_chain(policy_set)
    assert finding is not None
    assert finding.risk_level == RiskLevel.HIGH
    assert "*" in finding.extra["assumable_targets"]


# -------------------------------------------------------------------- #
# Wildcard expansion + Deny precedence                                 #
# -------------------------------------------------------------------- #


def test_iam_wildcard_triggers_many_findings(mock_policy, make_policy_set):
    """``iam:*`` should match every iam-prefixed required permission."""
    policy_set = make_policy_set(mock_policy("iam_wildcard"))
    findings = analyze(policy_set)
    technique_names = {f.technique_name for f in findings}
    assert "iam:CreatePolicyVersion" in technique_names
    assert "iam:CreateAccessKey" in technique_names
    assert "iam:UpdateAssumeRolePolicy" in technique_names
    assert "iam:AttachUserPolicy" in technique_names


def test_explicit_deny_suppresses_finding(mock_policy, make_policy_set):
    """An explicit Deny on iam:CreatePolicyVersion must hide that finding."""
    policy_set = make_policy_set(mock_policy("explicit_deny"))
    finding = check_create_policy_version(policy_set)
    assert finding is None
    findings = analyze(policy_set)
    assert all(f.technique_name != "iam:CreatePolicyVersion" for f in findings)


# -------------------------------------------------------------------- #
# analyze() ordering                                                   #
# -------------------------------------------------------------------- #


def test_findings_sorted_by_risk_level(mock_policy, make_policy_set):
    """CRITICAL findings should appear before HIGH/MEDIUM."""
    policy_set = make_policy_set(
        mock_policy("create_policy_version"),  # CRITICAL
        mock_policy("set_default_policy_version"),  # HIGH
        mock_policy("assume_role_wildcard"),  # HIGH
    )
    findings = analyze(policy_set)
    risks = [f.risk_level for f in findings]
    # Verify non-increasing risk priority.
    assert risks == sorted(risks, key=lambda r: -r.numeric)


def test_no_findings_returns_empty_list(make_policy_set):
    policy_set = make_policy_set({"Version": "2012-10-17", "Statement": []})
    assert analyze(policy_set) == []


def test_multi_action_passrole_lambda_partial_does_not_trigger(make_policy_set):
    """Lambda check needs all three perms; missing InvokeFunction => no finding."""
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:CreateFunction"],
                "Resource": "*",
            }
        ],
    }
    policy_set = make_policy_set(doc)
    finding = check_passrole_lambda(policy_set)
    assert finding is None


# -------------------------------------------------------------------- #
# Finding serialization                                                #
# -------------------------------------------------------------------- #


def test_finding_to_dict_round_trip(mock_policy, make_policy_set):
    policy_set = make_policy_set(mock_policy("create_policy_version"))
    finding = check_create_policy_version(policy_set)
    assert finding is not None
    payload = finding.to_dict()
    assert payload["technique_name"] == "iam:CreatePolicyVersion"
    assert payload["risk_level"] == "CRITICAL"
    assert isinstance(payload["required_permissions"], list)
    assert isinstance(payload["matched_permissions"], list)


def test_all_checks_registered():
    """ALL_CHECKS should include every check function we expose."""
    explicit = {
        check_create_policy_version,
        check_set_default_policy_version,
        check_passrole_ec2,
        check_passrole_lambda,
        check_passrole_glue,
        check_create_access_key,
        check_create_login_profile,
        check_update_login_profile,
        check_attach_user_policy,
        check_attach_role_policy,
        check_put_user_policy,
        check_add_user_to_group,
        check_assume_role_chain,
        check_update_assume_role_policy,
        check_passrole_cloudformation,
        check_passrole_codebuild,
    }
    assert explicit.issubset(set(ALL_CHECKS))
