"""Tests for IAM enumeration helpers.

Live AWS calls are stubbed — we validate the enumeration logic and the
PrincipalPolicySet helpers against synthetic input.
"""
from __future__ import annotations

from src.enumerator import (
    PolicyDocument,
    PrincipalPolicySet,
    assume_role_targets,
    build_policy_set_from_documents,
)
from src.utils import action_matches, actions_grant, parse_arn


# -------------------------------------------------------------------- #
# parse_arn / action matching                                          #
# -------------------------------------------------------------------- #


def test_parse_arn_user():
    parts = parse_arn("arn:aws:iam::123456789012:user/alice")
    assert parts.service == "iam"
    assert parts.account_id == "123456789012"
    assert parts.resource_type == "user"
    assert parts.resource_id == "alice"
    assert parts.is_user
    assert not parts.is_role


def test_parse_arn_role_arn():
    parts = parse_arn("arn:aws:iam::123456789012:role/AdminRole")
    assert parts.is_role
    assert parts.resource_id == "AdminRole"


def test_action_matches_wildcards():
    assert action_matches("iam:*", "iam:CreateUser")
    assert action_matches("iam:Create*", "iam:CreateAccessKey")
    assert not action_matches("iam:Create*", "iam:DeleteUser")
    assert action_matches("*", "anything:atall")


def test_actions_grant_with_wildcard():
    granted = ["iam:*", "s3:GetObject"]
    assert actions_grant(granted, "iam:CreatePolicyVersion")
    assert actions_grant(granted, "s3:GetObject")
    assert not actions_grant(granted, "ec2:RunInstances")


# -------------------------------------------------------------------- #
# PrincipalPolicySet helpers                                           #
# -------------------------------------------------------------------- #


def test_all_allowed_actions_collects_across_documents(make_policy_set, mock_policy):
    policy_set = make_policy_set(
        mock_policy("create_policy_version"),
        mock_policy("create_access_key"),
    )
    actions = policy_set.all_allowed_actions
    assert "iam:CreatePolicyVersion" in actions
    assert "iam:CreateAccessKey" in actions


def test_deny_actions_isolated_from_allow(make_policy_set, mock_policy):
    policy_set = make_policy_set(mock_policy("explicit_deny"))
    assert "iam:CreatePolicyVersion" in policy_set.deny_actions
    assert "iam:*" in policy_set.all_allowed_actions


def test_assume_role_targets_wildcard(make_policy_set, mock_policy):
    policy_set = make_policy_set(mock_policy("assume_role_wildcard"))
    assert "*" in assume_role_targets(policy_set)


def test_assume_role_targets_specific():
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": [
                    "arn:aws:iam::123456789012:role/RoleA",
                    "arn:aws:iam::123456789012:role/RoleB",
                ],
            }
        ],
    }
    policy_set = build_policy_set_from_documents(
        principal_arn="arn:aws:iam::123456789012:user/test",
        principal_type="user",
        documents=[doc],
    )
    targets = assume_role_targets(policy_set)
    assert "arn:aws:iam::123456789012:role/RoleA" in targets
    assert "arn:aws:iam::123456789012:role/RoleB" in targets


def test_build_policy_set_from_documents_metadata():
    doc = {"Version": "2012-10-17", "Statement": []}
    policy_set = build_policy_set_from_documents(
        principal_arn="arn:aws:iam::111111111111:role/MyRole",
        principal_type="role",
        documents=[doc],
    )
    assert policy_set.principal_name == "MyRole"
    assert policy_set.account_id == "111111111111"
    assert len(policy_set.policies) == 1


def test_statement_handles_single_dict_statement():
    """Some policies use a single Statement dict instead of a list."""
    doc = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "iam:CreatePolicyVersion",
            "Resource": "*",
        },
    }
    policy_set = build_policy_set_from_documents(
        principal_arn="arn:aws:iam::123456789012:user/test",
        principal_type="user",
        documents=[doc],
    )
    assert "iam:CreatePolicyVersion" in policy_set.all_allowed_actions


def test_policy_document_dataclass():
    pd = PolicyDocument(
        name="x",
        source="inline",
        arn=None,
        document={"Version": "2012-10-17", "Statement": []},
    )
    assert pd.name == "x"
    assert pd.arn is None


def test_principal_policy_set_groups_default_empty():
    policy_set = PrincipalPolicySet(
        principal_arn="arn:aws:iam::123456789012:user/u",
        principal_type="user",
        principal_name="u",
        account_id="123456789012",
    )
    assert policy_set.groups == []
    assert policy_set.policies == []
