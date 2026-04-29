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


def check_attach_user_policy(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:AttachUserPolicy — attach AdministratorAccess to self/any user."""
    required = ["iam:AttachUserPolicy"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:AttachUserPolicy",
        description=(
            "Principal can attach any managed policy (e.g. AdministratorAccess) "
            "to any IAM user, immediately granting them those permissions."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Restrict iam:AttachUserPolicy with a Condition restricting "
            "iam:PolicyARN to a small allowlist of approved managed policies. "
            "Never grant on Resource '*' without such guardrails."
        ),
        mitre_attack_ref="T1098",
    )


def check_attach_role_policy(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:AttachRolePolicy — give an assumable role admin permissions."""
    required = ["iam:AttachRolePolicy"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:AttachRolePolicy",
        description=(
            "Principal can attach AdministratorAccess (or any managed policy) "
            "to a role they can already assume — escalating that role's "
            "permissions to whatever the attached policy grants."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Constrain iam:AttachRolePolicy with iam:PolicyARN conditions and "
            "a tight Resource list of role ARNs. Apply Permissions Boundaries "
            "to restrict the maximum permissions roles can hold."
        ),
        mitre_attack_ref="T1098",
    )


def check_put_user_policy(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:PutUserPolicy — write a self-admin inline policy."""
    required = ["iam:PutUserPolicy"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:PutUserPolicy",
        description=(
            "Principal can create or replace inline policies on any IAM user, "
            "including themself. Writing an Allow:* / Resource:* inline policy "
            "grants full account access."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Replace iam:PutUserPolicy with managed-policy attachment workflows. "
            "If retained, scope Resource to ${aws:username} and apply a "
            "Permissions Boundary that caps maximum effective permissions."
        ),
        mitre_attack_ref="T1098",
    )


def check_add_user_to_group(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:AddUserToGroup — add self to admin group."""
    required = ["iam:AddUserToGroup"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:AddUserToGroup",
        description=(
            "Principal can add themself (or any user) to any IAM group. If a "
            "group like 'Admins' exists, membership immediately grants its "
            "policies."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Constrain iam:AddUserToGroup with a Resource list of allowed "
            "groups (e.g. project-specific groups) excluding privileged ones. "
            "Better: remove this permission and manage membership via your IdP."
        ),
        mitre_attack_ref="T1098",
    )


def check_assume_role_chain(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """sts:AssumeRole chains — recursive assume-role to higher privileges."""
    targets = assume_role_targets(policy_set)
    if not targets:
        return None
    # Wildcard target = can assume any role => clearly a chain risk.
    risky = [t for t in targets if t == "*" or t.endswith(":role/*")]
    if not risky and not targets:
        return None
    risk = RiskLevel.HIGH if risky else RiskLevel.MEDIUM
    description = (
        "Principal can assume one or more IAM roles via sts:AssumeRole. If any "
        "downstream role grants further AssumeRole permissions or is more "
        "privileged than this principal, the chain enables escalation. "
        "Recursive analysis to a depth of 3 is recommended."
    )
    return Finding(
        technique_name="sts:AssumeRole chain",
        description=description,
        required_permissions=["sts:AssumeRole"],
        matched_permissions=["sts:AssumeRole"],
        risk_level=risk,
        remediation=(
            "Audit each downstream role's trust policy and inline permissions. "
            "Avoid wildcard Resource on sts:AssumeRole. Use aws:SourceIdentity "
            "and ExternalId conditions for cross-account roles, and apply "
            "Permissions Boundaries on roles that can be widely assumed."
        ),
        mitre_attack_ref="T1548.005",
        extra={"assumable_targets": targets},
    )


def check_update_assume_role_policy(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """iam:UpdateAssumeRolePolicy — modify trust to allow self to assume."""
    required = ["iam:UpdateAssumeRolePolicy"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="iam:UpdateAssumeRolePolicy",
        description=(
            "Principal can rewrite the trust policy of any role, adding their "
            "own ARN as a trusted principal. They can then assume that role "
            "and inherit its permissions."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.CRITICAL,
        remediation=(
            "Restrict iam:UpdateAssumeRolePolicy to security-administration "
            "principals only, and protect privileged roles via SCPs that "
            "deny trust-policy modifications."
        ),
        mitre_attack_ref="T1098",
    )


def check_passrole_cloudformation(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """cloudformation:CreateStack + iam:PassRole — deploy privileged stacks."""
    required = ["iam:PassRole", "cloudformation:CreateStack"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="cloudformation:CreateStack + iam:PassRole",
        description=(
            "Principal can submit a CloudFormation stack template using a "
            "more privileged service role. The template can create arbitrary "
            "resources (admin users, roles, EC2s) under that role's "
            "permissions."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.HIGH,
        remediation=(
            "Restrict iam:PassRole resources to specific cloudformation "
            "service roles, and constrain CloudFormation actions with stack "
            "name patterns. Use iam:PassedToService=cloudformation.amazonaws.com "
            "and a Permissions Boundary on the deploy role."
        ),
        mitre_attack_ref="T1078.004",
    )


def check_passrole_codebuild(policy_set: PrincipalPolicySet) -> Optional[Finding]:
    """codebuild:CreateProject + iam:PassRole — execute build under privileged role."""
    required = ["iam:PassRole", "codebuild:CreateProject"]
    matched = _all_required_present(policy_set, required)
    if matched is None:
        return None
    return Finding(
        technique_name="codebuild:CreateProject + iam:PassRole",
        description=(
            "Principal can create a CodeBuild project that runs with a more "
            "privileged service role. The buildspec can execute arbitrary "
            "shell commands as that role and exfiltrate its credentials."
        ),
        required_permissions=required,
        matched_permissions=matched,
        risk_level=RiskLevel.HIGH,
        remediation=(
            "Limit iam:PassRole to a small allowlist of CodeBuild service roles. "
            "Audit buildspec sources (must be a trusted repo) and require a "
            "code-review gate on changes to buildspec.yml."
        ),
        mitre_attack_ref="T1059",
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
    check_attach_user_policy,
    check_attach_role_policy,
    check_put_user_policy,
    check_add_user_to_group,
    check_assume_role_chain,
    check_update_assume_role_policy,
    check_passrole_cloudformation,
    check_passrole_codebuild,
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
