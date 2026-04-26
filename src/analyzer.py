"""Privilege escalation detection rules.

Each rule consumes a :class:`PrincipalPolicySet` and returns a
:class:`Finding` if the principal has the permission combination required
for that escalation technique.

The catalog is based on Rhino Security Labs' 21 IAM privesc paths plus
common follow-ons. References:
    https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional

from .enumerator import PrincipalPolicySet, assume_role_targets
from .utils import actions_grant, get_logger


class RiskLevel(str, Enum):
    """Severity classifications for findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"

    @property
    def numeric(self) -> int:
        return {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}[self.value]


@dataclass
class Finding:
    """A single detected privilege escalation path."""

    technique_name: str
    description: str
    required_permissions: list[str]
    matched_permissions: list[str]
    risk_level: RiskLevel
    remediation: str
    mitre_attack_ref: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dictionary."""
        return {
            "technique_name": self.technique_name,
            "description": self.description,
            "required_permissions": list(self.required_permissions),
            "matched_permissions": list(self.matched_permissions),
            "risk_level": self.risk_level.value,
            "remediation": self.remediation,
            "mitre_attack_ref": self.mitre_attack_ref,
            "extra": self.extra,
        }


# A check is a function policy_set -> Optional[Finding]
CheckFn = Callable[[PrincipalPolicySet], Optional[Finding]]


def _granted_subset(
    policy_set: PrincipalPolicySet, required: Iterable[str]
) -> list[str]:
    """Return the subset of ``required`` actions present in ``policy_set``.

    Honors wildcard expansions (e.g. ``iam:*`` covers ``iam:CreateUser``) and
    explicit Deny statements.
    """
    granted = policy_set.all_allowed_actions
    denied = policy_set.deny_actions
    matched: list[str] = []
    for action in required:
        if not actions_grant(granted, action):
            continue
        if actions_grant(denied, action):
            continue
        matched.append(action)
    return matched


def _all_required_present(
    policy_set: PrincipalPolicySet, required: Iterable[str]
) -> Optional[list[str]]:
    """If every action in ``required`` is granted (and not denied), return them.

    Otherwise return None.
    """
    required_list = list(required)
    matched = _granted_subset(policy_set, required_list)
    if len(matched) == len(required_list):
        return matched
    return None


# -------------------------------------------------------------------- #
# Individual technique checks                                          #
# -------------------------------------------------------------------- #


def check_create_policy_version(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:CreatePolicyVersion — set a permissive default version on any managed policy."""
    required = ["iam:CreatePolicyVersion"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:CreatePolicyVersion",
        description=(
            "Principal can create a new version of an existing customer-managed "
            "policy and mark it as the default. By writing an Allow-everything "
            "statement into a policy already attached to a privileged identity, "
            "the principal effectively obtains full control of that identity."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Remove iam:CreatePolicyVersion from this principal, or constrain it "
            "with a Resource ARN list and a condition limiting the maximum policy "
            "version count. Prefer SCPs at the org level for sensitive actions."
        ),
        mitre_attack_ref="T1078.004",
    )


def check_set_default_policy_version(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:SetDefaultPolicyVersion — roll back to a stored permissive version."""
    required = ["iam:SetDefaultPolicyVersion"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:SetDefaultPolicyVersion",
        description=(
            "Principal can re-activate any non-default version of a managed "
            "policy. If a policy has historical versions that were broader than "
            "the current default, the principal can revert and inherit those "
            "permissions."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.HIGH,
        remediation=(
            "Audit non-default versions of customer-managed policies and delete "
            "ones that grant excessive privilege. Restrict iam:SetDefaultPolicyVersion "
            "to admin principals only."
        ),
        mitre_attack_ref="T1078.004",
    )


def check_passrole_ec2(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:PassRole + ec2:RunInstances — boot an instance under a privileged role."""
    required = ["iam:PassRole", "ec2:RunInstances"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:PassRole + ec2:RunInstances",
        description=(
            "Principal can launch an EC2 instance with an IAM instance profile "
            "attached. By choosing a more privileged role, then connecting to the "
            "instance (SSH, SSM, or instance metadata exfiltration), the attacker "
            "obtains credentials for that role."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Constrain iam:PassRole with a Resource ARN list of approved instance "
            "profile roles only, and require IMDSv2 with hop-limit=1. Use "
            "iam:PassedToService condition keys to restrict which services can "
            "be passed which roles."
        ),
        mitre_attack_ref="T1078.004",
    )


def check_passrole_lambda(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction."""
    required = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
        description=(
            "Principal can deploy a Lambda function with an arbitrary execution "
            "role and invoke it. The function code runs as that role, granting "
            "the attacker full programmatic use of its permissions."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Restrict iam:PassRole to a strict allowlist of execution roles via "
            "Resource. Add an iam:PassedToService=lambda.amazonaws.com condition "
            "to scope where roles can be passed. Consider Permissions Boundaries "
            "on developer principals."
        ),
        mitre_attack_ref="T1059",
    )


def check_passrole_glue(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:PassRole + glue:CreateDevEndpoint — SSH into a notebook with privileged role."""
    required = ["iam:PassRole", "glue:CreateDevEndpoint"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:PassRole + glue:CreateDevEndpoint",
        description=(
            "Principal can spin up a Glue Development Endpoint attached to a "
            "more privileged role and SSH into it. Once inside, the attacker "
            "can read role credentials from the EC2 metadata service of the "
            "underlying instance."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.HIGH,
        remediation=(
            "Tightly scope iam:PassRole to a small list of Glue roles, prefer "
            "Glue jobs over dev endpoints, and disable public network access on "
            "any required dev endpoints."
        ),
        mitre_attack_ref="T1078.004",
    )


def check_create_access_key(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:CreateAccessKey — issue keys for any user (lateral movement)."""
    required = ["iam:CreateAccessKey"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:CreateAccessKey",
        description=(
            "Principal can create programmatic access keys for any IAM user, "
            "including admins. With a Resource value of '*' (or no resource "
            "constraint) this enables direct lateral movement to any user "
            "in the account."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Restrict iam:CreateAccessKey with a Resource of "
            "${aws:username} so users can only manage their own keys. Monitor "
            "for CreateAccessKey calls where the target user differs from the "
            "caller in CloudTrail."
        ),
        mitre_attack_ref="T1098.001",
    )


def check_create_login_profile(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:CreateLoginProfile — issue console password to passwordless user."""
    required = ["iam:CreateLoginProfile"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:CreateLoginProfile",
        description=(
            "Principal can create a console login profile (password) for any "
            "IAM user that doesn't already have one. This grants console access "
            "as that user without needing their consent or notification."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Limit iam:CreateLoginProfile with a Resource of ${aws:username}, "
            "or remove it entirely from non-admin principals. Enforce MFA on "
            "all console-enabled users."
        ),
        mitre_attack_ref="T1098.001",
    )


def check_update_login_profile(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:UpdateLoginProfile — change another user's password."""
    required = ["iam:UpdateLoginProfile"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:UpdateLoginProfile",
        description=(
            "Principal can reset the console password of any IAM user, then "
            "log in as that user. This is the password-update equivalent of "
            "CreateLoginProfile."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Restrict iam:UpdateLoginProfile with Resource: ${aws:username}. "
            "Require MFA via aws:MultiFactorAuthPresent condition. Alert on "
            "UpdateLoginProfile events targeting users other than the caller."
        ),
        mitre_attack_ref="T1098.001",
    )


# Ordered registry — used to drive the analyzer loop and the report.
ALL_CHECKS: list[CheckFn] = [
    check_create_policy_version,
    check_set_default_policy_version,
    check_passrole_ec2,
    check_passrole_lambda,
    check_passrole_glue,
    check_create_access_key,
    check_create_login_profile,
    check_update_login_profile,
]


def analyze(policy_set: PrincipalPolicySet) -> list[Finding]:
    """Run every check against ``policy_set`` and return all findings.

    Findings are sorted by risk level (CRITICAL first), then by technique name
    for stable output.
    """
    logger = get_logger()
    logger.debug("Running %d analyzer checks", len(ALL_CHECKS))
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            finding = check(policy_set)
        except Exception as exc:  # noqa: BLE001 — guard against malformed docs
            logger.warning("Check %s raised %s", check.__name__, exc)
            continue
        if finding is not None:
            findings.append(finding)
    findings.sort(
        key=lambda f: (-f.risk_level.numeric, f.technique_name.lower())
    )
    return findings
