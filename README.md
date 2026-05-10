# aws-iam-privesc-finder

![CI](https://github.com/Akhil-1527/aws-iam-privesc-finder/actions/workflows/ci.yml/badge.svg)

A Python CLI that analyzes the IAM policies attached to a target AWS user or
role and identifies known **privilege escalation paths** before an attacker
does. Built for authorized red team engagements and internal cloud security
review.

> ⚠️ **Authorized testing only.** Run this against AWS accounts you own or
> have explicit written permission to assess. See [Disclaimer](#disclaimer).

## Features

- **16 privesc techniques** covered out of the box (see [Detected techniques](#detected-techniques))
- **Static, read-only analysis** — works with `arn:aws:iam::aws:policy/ReadOnlyAccess` credentials
- **Markdown and JSON reports** with MITRE ATT&CK mapping and remediation guidance
- **Rich-formatted CLI output** with color-coded risk levels
- **Sigma rules** for runtime detection in CloudTrail
- **CI-friendly exit codes** — exit `2` when findings exist, `0` when clean

## Installation

```bash
git clone https://github.com/Akhil-1527/aws-iam-privesc-finder.git
cd aws-iam-privesc-finder
pip install -r requirements.txt
pip install -e .
```

Python 3.10+ required.

## Usage

```bash
# Analyze a user using your default AWS profile
aws-privesc-finder --user alice

# Analyze a role with a specific profile, write both report formats
aws-privesc-finder \
    --profile staging \
    --role-arn arn:aws:iam::123456789012:role/DevRole \
    --output both \
    --output-dir ./reports

# Analyze a user, JSON only (pipe into your SIEM/SOAR)
aws-privesc-finder --user bob --output json --no-console > findings.json

# Verbose mode for debugging permissions issues during enumeration
aws-privesc-finder --user alice --verbose
```

### CLI flags

| Flag             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `--profile`      | AWS profile name (defaults to environment / default profile).  |
| `--region`       | Region override (most IAM API calls are region-agnostic).      |
| `--user`         | IAM user name to analyze.                                      |
| `--role-arn`     | IAM role ARN (or role name) to analyze.                        |
| `--output`       | `console` (default), `markdown`, `json`, or `both`.            |
| `--output-dir`   | Where to write report files (default: current dir).            |
| `--report-name`  | Base filename for report files (default: `privesc-report`).    |
| `--no-console`   | Suppress the Rich console summary (useful when piping JSON).   |
| `--verbose`      | Debug-level logging.                                           |

### Sample output

```
─────────────────── Privesc Finder ───────────────────
AWS IAM Privesc Finder v1.0
Target: arn:aws:iam::123456789012:user/test
Policies examined: 3
──────────────────────────────────────────────────────
FINDINGS (2 critical, 1 high)

  #  Risk      Technique                                          MITRE      Matched Permissions
─────────────────────────────────────────────────────────────────────────────────────────────────
  1  CRITICAL  iam:CreatePolicyVersion                            T1078.004  iam:CreatePolicyVersion
  2  CRITICAL  iam:PassRole + lambda:CreateFunction +             T1059      iam:PassRole, lambda:CreateFunction,
              lambda:InvokeFunction                                          lambda:InvokeFunction
  3  HIGH      sts:AssumeRole chain                               T1548.005  sts:AssumeRole

[CRITICAL] iam:CreatePolicyVersion
  Permissions matched: iam:CreatePolicyVersion
  Remediation: Remove iam:CreatePolicyVersion from this principal, or constrain
               it with a Resource ARN list and a condition limiting the maximum
               policy version count.
  MITRE: T1078.004
```

## Detected techniques

Each rule is documented in [`docs/techniques.md`](docs/techniques.md).

| # | Technique | Risk | MITRE |
| - | --------- | ---- | ----- |
| 1 | `iam:CreatePolicyVersion` | CRITICAL | T1078.004 |
| 2 | `iam:SetDefaultPolicyVersion` | HIGH | T1078.004 |
| 3 | `iam:PassRole` + `ec2:RunInstances` | CRITICAL | T1078.004 |
| 4 | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | CRITICAL | T1059 |
| 5 | `iam:PassRole` + `glue:CreateDevEndpoint` | HIGH | T1078.004 |
| 6 | `iam:CreateAccessKey` | CRITICAL | T1098.001 |
| 7 | `iam:CreateLoginProfile` | CRITICAL | T1098.001 |
| 8 | `iam:UpdateLoginProfile` | CRITICAL | T1098.001 |
| 9 | `iam:AttachUserPolicy` | CRITICAL | T1098 |
| 10 | `iam:AttachRolePolicy` | CRITICAL | T1098 |
| 11 | `iam:PutUserPolicy` | CRITICAL | T1098 |
| 12 | `iam:AddUserToGroup` | CRITICAL | T1098 |
| 13 | `sts:AssumeRole` chain | HIGH/MEDIUM | T1548.005 |
| 14 | `iam:UpdateAssumeRolePolicy` | CRITICAL | T1098 |
| 15 | `cloudformation:CreateStack` + `iam:PassRole` | HIGH | T1078.004 |
| 16 | `codebuild:CreateProject` + `iam:PassRole` | HIGH | T1059 |

## Detection guidance

Static analysis tells you *who could* escalate. Pair it with the Sigma rules
in [`detections/sigma/iam_privesc_techniques.yml`](detections/sigma/iam_privesc_techniques.yml)
to alert when escalation is *attempted at runtime*.

Convert to your SIEM with [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
pip install pysigma pysigma-backend-splunk pysigma-pipeline-aws
sigma convert -t splunk -p cloudtrail detections/sigma/iam_privesc_techniques.yml
```

Suggested CloudTrail alerts:

- **`iam:CreatePolicyVersion` with `setAsDefault=true`** — investigate every occurrence
- **`iam:CreateAccessKey` where `requestParameters.userName != userIdentity.userName`** — lateral movement signal
- **`iam:UpdateLoginProfile` on another user** — account takeover pattern
- **`iam:AttachUserPolicy` / `AttachRolePolicy` of `AdministratorAccess`** — escalation alert
- **AssumeRole chains** where `userIdentity.type=AssumedRole` calls AssumeRole again

## Required IAM permissions

The tool only reads — it never modifies state. Recommended attached policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

`AccessDenied` errors are handled gracefully and logged at DEBUG; missing
policies simply don't show up in the findings.

## Limitations

The current implementation evaluates **identity-based policies** only. It does
not yet model:

- Resource-based policies (S3 bucket policies, KMS key policies, Lambda resource policies, ...)
- Service Control Policies (SCPs) or Permission Boundaries
- Session policies passed at AssumeRole time
- Condition keys (`aws:RequestTag`, `aws:SourceIp`, MFA, ...)
- Cross-account trust policy nuance (ExternalId, etc.)

Treat a clean report as "no statically-detectable identity-policy path",
**not** "the principal is safe under all conditions". Combine with manual
review and runtime detections.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

The test suite covers all 16 detection rules with positive and negative
cases plus enumerator/reporter unit tests.

## References

- Spencer Gietzen, [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (Rhino Security Labs)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework
- [PMapper](https://github.com/nccgroup/PMapper) — Principal-mapping IAM analyzer
- [MITRE ATT&CK – Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/aws/)

## Disclaimer

This tool is intended **for authorized security assessments only**. Running it
against accounts you do not own or have explicit written permission to test
may violate the AWS Acceptable Use Policy and applicable laws. The authors
accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
