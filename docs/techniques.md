# Privilege Escalation Techniques

Detailed reference for every technique implemented in
`src/analyzer.py`. Each section explains the attacker workflow, the IAM
permissions required, the detection signal in CloudTrail, and the recommended
remediation.

The catalog is anchored in Spencer Gietzen's research at Rhino Security Labs,
extended with a few common follow-ons.

---

## 1. `iam:CreatePolicyVersion`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1078.004

**Workflow.** A managed IAM policy can hold up to five versions, only one of
which is "default". `CreatePolicyVersion` accepts a `SetAsDefault=true` flag.
If the principal can call this on any policy attached to a privileged
identity (or themself), they can write a permissive document into a new
version, set it as default, and inherit those permissions immediately.

**Required permissions:** `iam:CreatePolicyVersion`

**Detection.** CloudTrail event `CreatePolicyVersion` with
`requestParameters.setAsDefault=true`.

**Remediation.** Remove `iam:CreatePolicyVersion` from non-admin principals,
or constrain it with a `Resource` allowlist. Apply SCPs at the org level on
sensitive policies.

---

## 2. `iam:SetDefaultPolicyVersion`

**Risk:** HIGH · **MITRE ATT&CK:** T1078.004

**Workflow.** Even without creating a new version, an attacker can revert a
policy to a previously-existing permissive version, inheriting whatever it
allowed at the time of authoring.

**Required permissions:** `iam:SetDefaultPolicyVersion`

**Detection.** `SetDefaultPolicyVersion` events in CloudTrail (the rule fires
on every successful call — combine with allowlists for change-management).

**Remediation.** Audit and prune non-default versions of customer-managed
policies. Restrict `SetDefaultPolicyVersion` to break-glass admin only.

---

## 3. `iam:PassRole` + `ec2:RunInstances`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1078.004

**Workflow.** Launch an EC2 instance with an IAM instance profile attached
(`IamInstanceProfile=Arn:...`). The principal then SSHes / SSMs into the
instance, queries IMDSv2 (`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`),
and walks away with that role's credentials.

**Required permissions:** `iam:PassRole`, `ec2:RunInstances`

**Detection.** `RunInstances` events with `requestParameters.iamInstanceProfile`
populated; correlate with subsequent `iam:GetRolePolicy` or sensitive STS calls
from the new instance.

**Remediation.** Constrain `PassRole` with a Resource allowlist of approved
profiles. Enforce IMDSv2 with `HttpPutResponseHopLimit=1`. Use the
`iam:PassedToService` condition key.

---

## 4. `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1059

**Workflow.** Deploy a Lambda whose execution role is more privileged than
the caller's, then invoke it. The function code runs as that role and can
exfiltrate or proxy further commands.

**Required permissions:** `iam:PassRole`, `lambda:CreateFunction`,
`lambda:InvokeFunction`

**Detection.** `CreateFunction` followed by `InvokeFunction` calls from the
same principal where the function role differs from the caller's identity.

**Remediation.** Limit `PassRole` Resource to a known list of execution
roles. Apply Permissions Boundaries on developer principals so even with this
combo they can't escalate beyond a maximum.

---

## 5. `iam:PassRole` + `glue:CreateDevEndpoint`

**Risk:** HIGH · **MITRE ATT&CK:** T1078.004

**Workflow.** Glue Dev Endpoints provide an SSH-accessible Spark notebook
environment. Spinning one up with a privileged Glue role and SSHing in
exposes the role's credentials via the underlying instance metadata.

**Required permissions:** `iam:PassRole`, `glue:CreateDevEndpoint`

**Detection.** `CreateDevEndpoint` events. Cross-reference with subsequent
SSH access via VPC flow logs.

**Remediation.** Prefer Glue Jobs over dev endpoints. Constrain the role
list aggressively.

---

## 6. `iam:CreateAccessKey`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098.001

**Workflow.** Create a programmatic access key for *another* user — most
commonly an admin — and authenticate as that user.

**Required permissions:** `iam:CreateAccessKey`

**Detection.** Alert when `requestParameters.userName !=
userIdentity.userName`. Self-rotation is benign; cross-user creation is
suspicious.

**Remediation.** Restrict with `Resource: arn:aws:iam::<acct>:user/${aws:username}`.

---

## 7. `iam:CreateLoginProfile`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098.001

**Workflow.** Many programmatic IAM users have no console password. Calling
`CreateLoginProfile` for them assigns one — the attacker then logs into the
console as that user.

**Required permissions:** `iam:CreateLoginProfile`

**Detection.** `CreateLoginProfile` events targeting a user other than the
caller.

**Remediation.** Restrict with `Resource: ${aws:username}`. Enforce MFA on
all console-enabled users.

---

## 8. `iam:UpdateLoginProfile`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098.001

**Workflow.** Reset another user's password and log in as them. Equivalent
to `CreateLoginProfile` but for users who already have a password.

**Required permissions:** `iam:UpdateLoginProfile`

**Detection.** `UpdateLoginProfile` events where the target differs from
the caller.

**Remediation.** Same as `CreateLoginProfile`. Add an MFA condition.

---

## 9. `iam:AttachUserPolicy`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098

**Workflow.** Attach `AdministratorAccess` (or any broad managed policy) to
a user — including yourself.

**Required permissions:** `iam:AttachUserPolicy`

**Detection.** `AttachUserPolicy` events where `requestParameters.policyArn`
contains `AdministratorAccess` / `IAMFullAccess` / `PowerUserAccess`.

**Remediation.** Add a Condition restricting `iam:PolicyARN` to an
allowlist of approved managed policies.

---

## 10. `iam:AttachRolePolicy`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098

**Workflow.** Attach AdministratorAccess to a role you can already assume,
then assume it.

**Required permissions:** `iam:AttachRolePolicy`

**Detection.** `AttachRolePolicy` events. Same `policyArn` allowlist
heuristic as `AttachUserPolicy`.

**Remediation.** Same Condition strategy. Apply Permissions Boundaries on
roles to cap their max effective permissions regardless of attached policies.

---

## 11. `iam:PutUserPolicy`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098

**Workflow.** Write an inline policy granting `Action: *` `Resource: *` to
yourself (or another user).

**Required permissions:** `iam:PutUserPolicy`

**Detection.** `PutUserPolicy` events with permissive policy documents.

**Remediation.** Replace inline-policy workflows with managed-policy
attachment. If retained, scope `Resource: ${aws:username}`.

---

## 12. `iam:AddUserToGroup`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098

**Workflow.** Add yourself to a privileged group (e.g. `Admins`).

**Required permissions:** `iam:AddUserToGroup`

**Detection.** `AddUserToGroup` events where the target user is the caller
and the target group is privileged.

**Remediation.** Constrain `Resource` to project-specific groups, never
`*`. Manage privileged group membership via your IdP, not directly.

---

## 13. `sts:AssumeRole` chains

**Risk:** HIGH (wildcard target) / MEDIUM (specific) · **MITRE ATT&CK:** T1548.005

**Workflow.** A principal that can assume one or more roles can chain
through them — each assumed role may have its own AssumeRole permissions
on yet more privileged roles. The static analyzer recommends recursive
analysis up to 3 hops.

**Required permissions:** `sts:AssumeRole` (with relevant Resource targets)

**Detection.** Heuristic: `AssumeRole` events where
`userIdentity.type=AssumedRole` indicate chaining. Multiple consecutive
assumes within seconds is high-signal.

**Remediation.** Avoid wildcard Resource on `sts:AssumeRole`. Use
`aws:SourceIdentity` and `ExternalId` conditions for cross-account roles.

---

## 14. `iam:UpdateAssumeRolePolicy`

**Risk:** CRITICAL · **MITRE ATT&CK:** T1098

**Workflow.** Rewrite the trust policy of any role to add your ARN as a
trusted principal, then assume it.

**Required permissions:** `iam:UpdateAssumeRolePolicy`

**Detection.** `UpdateAssumeRolePolicy` events. Diff the new
`policyDocument` against the prior version to spot principal additions.

**Remediation.** Restrict to security-administration only. SCP-deny on
sensitive role ARNs.

---

## 15. `cloudformation:CreateStack` + `iam:PassRole`

**Risk:** HIGH · **MITRE ATT&CK:** T1078.004

**Workflow.** Submit a CloudFormation template using a more-privileged
service role (`--role-arn`). The template can create admin users, roles, or
EC2s under that role's permissions, even if the caller couldn't directly.

**Required permissions:** `cloudformation:CreateStack`, `iam:PassRole`

**Detection.** `CreateStack` / `UpdateStack` events with
`requestParameters.roleArn` populated.

**Remediation.** Constrain `PassRole` to specific stack-deploy service
roles. Apply Permissions Boundaries to those service roles to bound the
maximum resource set they can create.

---

## 16. `codebuild:CreateProject` + `iam:PassRole`

**Risk:** HIGH · **MITRE ATT&CK:** T1059

**Workflow.** Create a CodeBuild project whose service role is more
privileged. The buildspec runs arbitrary commands as that role and can
exfiltrate its credentials.

**Required permissions:** `codebuild:CreateProject`, `iam:PassRole`

**Detection.** `CreateProject` + `StartBuild` events with
`requestParameters.serviceRole` populated.

**Remediation.** Limit `PassRole` to a small allowlist of build roles. Use
trusted source repositories only and gate buildspec changes behind code
review.

---

## Adding new techniques

1. Add a `check_<name>(policy_set) -> Optional[Finding]` to `src/analyzer.py`.
2. Append to the `ALL_CHECKS` registry.
3. Add a mock policy under `tests/mock_policies/`.
4. Parametrize the technique in `tests/test_analyzer.py`.
5. Add a Sigma rule in `detections/sigma/iam_privesc_techniques.yml` if a
   distinct CloudTrail event is involved.
6. Document it here and in `README.md`'s technique table.
