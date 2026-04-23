"""IAM policy enumeration for a target user or role.

Collects every policy statement that applies to the principal:
  * Attached managed policies (inc. AWS-managed)
  * Inline user/role policies
  * For users: policies attached to groups they belong to (managed + inline)
  * Trust policy of roles (used for AssumeRole chain analysis)

The output is a normalized :class:`PrincipalPolicySet` that the analyzer
consumes without needing further AWS calls.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .utils import (
    build_iam_client,
    build_sts_client,
    expand_actions,
    expand_resources,
    get_logger,
    parse_arn,
    safe_call,
)


@dataclass
class PolicyDocument:
    """One policy attached to the principal, with its parsed document."""

    name: str
    source: str  # e.g. "managed", "inline", "group:Devs/inline", "trust"
    arn: Optional[str]
    document: dict


@dataclass
class PrincipalPolicySet:
    """All policy material that applies to a single principal."""

    principal_arn: str
    principal_type: str  # "user" or "role"
    principal_name: str
    account_id: str
    policies: list[PolicyDocument] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    trust_policy: Optional[dict] = None

    @property
    def all_allowed_actions(self) -> set[str]:
        """Union of every Allow-action across every attached statement.

        Wildcards (e.g. ``iam:*``) are kept as-is — match resolution happens
        in :func:`utils.action_matches`.
        """
        actions: set[str] = set()
        for policy in self.policies:
            for stmt in _statements(policy.document):
                if stmt.get("Effect") != "Allow":
                    continue
                for action in expand_actions(stmt.get("Action")):
                    actions.add(action)
        return actions

    @property
    def deny_actions(self) -> set[str]:
        """Union of every explicit Deny-action across statements."""
        denies: set[str] = set()
        for policy in self.policies:
            for stmt in _statements(policy.document):
                if stmt.get("Effect") != "Deny":
                    continue
                for action in expand_actions(stmt.get("Action")):
                    denies.add(action)
        return denies

    def allow_statements(self) -> list[dict]:
        """All Allow statements across all attached policies (flattened)."""
        out: list[dict] = []
        for policy in self.policies:
            for stmt in _statements(policy.document):
                if stmt.get("Effect") == "Allow":
                    out.append(stmt)
        return out


def _statements(document: dict) -> list[dict]:
    """Return the Statement list (always a list, even if doc has a single dict)."""
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [s for s in statements if isinstance(s, dict)]
    return []


def _normalize_document(doc: Any) -> dict:
    """Policy documents come back URL-encoded JSON or as dicts depending on call."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except json.JSONDecodeError:
            return {}
    return {}


class IAMEnumerator:
    """Enumerate all policies attached to a user or role using boto3."""

    def __init__(self, session) -> None:
        self.session = session
        self.iam = build_iam_client(session)
        self.sts = build_sts_client(session)
        self.logger = get_logger()

    def get_caller_account_id(self) -> Optional[str]:
        """Best-effort sts:GetCallerIdentity to discover the current account."""
        result = safe_call(self.sts.get_caller_identity)
        if result:
            return result.get("Account")
        return None

    def enumerate_user(self, user_name: str) -> PrincipalPolicySet:
        """Collect all policies that apply to an IAM user.

        Includes group memberships, attached managed policies, inline user
        policies, and inline/managed policies attached to those groups.
        """
        self.logger.info("Enumerating policies for user [bold]%s[/bold]", user_name)

        account_id = self.get_caller_account_id() or "000000000000"
        principal_arn = f"arn:aws:iam::{account_id}:user/{user_name}"

        policies: list[PolicyDocument] = []

        # Attached managed user policies
        attached = self._list_attached_user_policies(user_name)
        for entry in attached:
            doc = self._fetch_managed_policy(entry["PolicyArn"])
            if doc is not None:
                policies.append(
                    PolicyDocument(
                        name=entry["PolicyName"],
                        source="managed",
                        arn=entry["PolicyArn"],
                        document=doc,
                    )
                )

        # Inline user policies
        for inline_name in self._list_user_policy_names(user_name):
            doc = self._fetch_user_inline_policy(user_name, inline_name)
            if doc is not None:
                policies.append(
                    PolicyDocument(
                        name=inline_name,
                        source="inline",
                        arn=None,
                        document=doc,
                    )
                )

        # Group-attached policies
        groups = self._list_groups_for_user(user_name)
        for group_name in groups:
            for entry in self._list_attached_group_policies(group_name):
                doc = self._fetch_managed_policy(entry["PolicyArn"])
                if doc is not None:
                    policies.append(
                        PolicyDocument(
                            name=entry["PolicyName"],
                            source=f"group:{group_name}/managed",
                            arn=entry["PolicyArn"],
                            document=doc,
                        )
                    )
            for inline_name in self._list_group_policy_names(group_name):
                doc = self._fetch_group_inline_policy(group_name, inline_name)
                if doc is not None:
                    policies.append(
                        PolicyDocument(
                            name=inline_name,
                            source=f"group:{group_name}/inline",
                            arn=None,
                            document=doc,
                        )
                    )

        return PrincipalPolicySet(
            principal_arn=principal_arn,
            principal_type="user",
            principal_name=user_name,
            account_id=account_id,
            policies=policies,
            groups=groups,
        )

    def enumerate_role(self, role_arn_or_name: str) -> PrincipalPolicySet:
        """Collect all policies that apply to an IAM role.

        Accepts either a role name or a full role ARN.
        """
        if role_arn_or_name.startswith("arn:"):
            parts = parse_arn(role_arn_or_name)
            role_name = parts.resource_id
            account_id = parts.account_id
            principal_arn = role_arn_or_name
        else:
            role_name = role_arn_or_name
            account_id = self.get_caller_account_id() or "000000000000"
            principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        self.logger.info("Enumerating policies for role [bold]%s[/bold]", role_name)

        policies: list[PolicyDocument] = []
        trust_policy: Optional[dict] = None

        role = safe_call(self.iam.get_role, RoleName=role_name)
        if role is not None:
            trust_policy = _normalize_document(
                role.get("Role", {}).get("AssumeRolePolicyDocument")
            )
            if trust_policy:
                policies.append(
                    PolicyDocument(
                        name=f"{role_name}-trust",
                        source="trust",
                        arn=None,
                        document=trust_policy,
                    )
                )

        for entry in self._list_attached_role_policies(role_name):
            doc = self._fetch_managed_policy(entry["PolicyArn"])
            if doc is not None:
                policies.append(
                    PolicyDocument(
                        name=entry["PolicyName"],
                        source="managed",
                        arn=entry["PolicyArn"],
                        document=doc,
                    )
                )

        for inline_name in self._list_role_policy_names(role_name):
            doc = self._fetch_role_inline_policy(role_name, inline_name)
            if doc is not None:
                policies.append(
                    PolicyDocument(
                        name=inline_name,
                        source="inline",
                        arn=None,
                        document=doc,
                    )
                )

        return PrincipalPolicySet(
            principal_arn=principal_arn,
            principal_type="role",
            principal_name=role_name,
            account_id=account_id,
            policies=policies,
            trust_policy=trust_policy,
        )

    # ------------------------------------------------------------------
    # Pagination helpers — boto3 paginators with safe_call wrapping.
    # ------------------------------------------------------------------

    def _paginate(self, client_method_name: str, key: str, **kwargs) -> list[dict]:
        """Run a paginated IAM list_* call and collect ``key`` from each page."""
        paginator = self.iam.get_paginator(client_method_name)
        results: list[dict] = []
        try:
            for page in paginator.paginate(**kwargs):
                results.extend(page.get(key, []))
        except Exception as exc:  # noqa: BLE001 — swallow with logging for read-only friendliness
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {
                    "AccessDenied",
                    "AccessDeniedException",
                    "NoSuchEntity",
                    "NoSuchEntityException",
                }:
                    self.logger.debug(
                        "Skipping %s due to %s", client_method_name, code
                    )
                    return []
            self.logger.warning("Pagination error in %s: %s", client_method_name, exc)
            return results
        return results

    def _list_attached_user_policies(self, user_name: str) -> list[dict]:
        return self._paginate(
            "list_attached_user_policies",
            "AttachedPolicies",
            UserName=user_name,
        )

    def _list_user_policy_names(self, user_name: str) -> list[str]:
        return self._paginate(
            "list_user_policies",
            "PolicyNames",
            UserName=user_name,
        )

    def _list_groups_for_user(self, user_name: str) -> list[str]:
        groups = self._paginate(
            "list_groups_for_user",
            "Groups",
            UserName=user_name,
        )
        return [g.get("GroupName") for g in groups if g.get("GroupName")]

    def _list_attached_group_policies(self, group_name: str) -> list[dict]:
        return self._paginate(
            "list_attached_group_policies",
            "AttachedPolicies",
            GroupName=group_name,
        )

    def _list_group_policy_names(self, group_name: str) -> list[str]:
        return self._paginate(
            "list_group_policies",
            "PolicyNames",
            GroupName=group_name,
        )

    def _list_attached_role_policies(self, role_name: str) -> list[dict]:
        return self._paginate(
            "list_attached_role_policies",
            "AttachedPolicies",
            RoleName=role_name,
        )

    def _list_role_policy_names(self, role_name: str) -> list[str]:
        return self._paginate(
            "list_role_policies",
            "PolicyNames",
            RoleName=role_name,
        )

    # ------------------------------------------------------------------
    # Single-policy fetchers
    # ------------------------------------------------------------------

    def _fetch_managed_policy(self, policy_arn: str) -> Optional[dict]:
        meta = safe_call(self.iam.get_policy, PolicyArn=policy_arn)
        if not meta:
            return None
        version_id = meta.get("Policy", {}).get("DefaultVersionId")
        if not version_id:
            return None
        version = safe_call(
            self.iam.get_policy_version,
            PolicyArn=policy_arn,
            VersionId=version_id,
        )
        if not version:
            return None
        doc = version.get("PolicyVersion", {}).get("Document")
        return _normalize_document(doc) if doc else None

    def _fetch_user_inline_policy(self, user_name: str, policy_name: str) -> Optional[dict]:
        result = safe_call(
            self.iam.get_user_policy, UserName=user_name, PolicyName=policy_name
        )
        if not result:
            return None
        return _normalize_document(result.get("PolicyDocument"))

    def _fetch_role_inline_policy(self, role_name: str, policy_name: str) -> Optional[dict]:
        result = safe_call(
            self.iam.get_role_policy, RoleName=role_name, PolicyName=policy_name
        )
        if not result:
            return None
        return _normalize_document(result.get("PolicyDocument"))

    def _fetch_group_inline_policy(self, group_name: str, policy_name: str) -> Optional[dict]:
        result = safe_call(
            self.iam.get_group_policy, GroupName=group_name, PolicyName=policy_name
        )
        if not result:
            return None
        return _normalize_document(result.get("PolicyDocument"))


def build_policy_set_from_documents(
    principal_arn: str,
    principal_type: str,
    documents: list[dict],
) -> PrincipalPolicySet:
    """Construct a PrincipalPolicySet directly from raw policy documents.

    Used by tests and offline analysis where AWS calls are not desired.
    """
    parts = parse_arn(principal_arn)
    policies = [
        PolicyDocument(
            name=f"policy-{i}",
            source="inline",
            arn=None,
            document=doc,
        )
        for i, doc in enumerate(documents)
    ]
    return PrincipalPolicySet(
        principal_arn=principal_arn,
        principal_type=principal_type,
        principal_name=parts.resource_id,
        account_id=parts.account_id,
        policies=policies,
    )


def assume_role_targets(policy_set: PrincipalPolicySet) -> list[str]:
    """Return all role ARNs (or wildcards) the principal can assume.

    Looks at every Allow-statement that grants ``sts:AssumeRole`` and
    collects the Resource entries.
    """
    targets: list[str] = []
    for stmt in policy_set.allow_statements():
        actions = expand_actions(stmt.get("Action"))
        if any(a.lower() == "sts:assumerole" or a == "*" or a.lower() == "sts:*" for a in actions):
            for resource in expand_resources(stmt.get("Resource")):
                targets.append(resource)
    return targets
