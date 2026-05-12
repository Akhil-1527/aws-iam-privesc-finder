# Security Policy

The maintainers of `aws-iam-privesc-finder` take the security of this project
seriously. This document describes how to report vulnerabilities, what is
considered in scope, and how we coordinate disclosure with reporters.

## Supported Versions

Security fixes are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No                 |

When a new minor or major version is released, the previous line will receive
critical security fixes for a transition period announced in the release
notes.

## Reporting a Vulnerability

Please report vulnerabilities through GitHub Private Vulnerability Disclosure
on this repository:

1. Open the repository on GitHub.
2. Click **Security**, then **Report a vulnerability**.
3. Fill out the advisory form with the details described below.

Do not file a public GitHub issue for security reports. Public issues are
appropriate for functional bug reports only.

### What to include in a report

A high quality report contains:

* **Description.** A short summary of the issue and the affected component
  (for example, `src/analyzer.py`, a specific detection rule, or the report
  rendering pipeline).
* **Reproduction steps.** A minimal sequence of commands or inputs that
  reliably reproduces the issue. Include the version of the tool, the Python
  version, and the operating system.
* **Impact assessment.** What an attacker could achieve by exploiting the
  issue. Be explicit about prerequisites such as required permissions, local
  access, or specific AWS configurations.
* **Suggested remediation.** Optional, but appreciated. A patch, a sketch of
  a fix, or a reference to comparable mitigations elsewhere all help us
  triage and ship faster.

If you believe the report contains sensitive material that should not be
written to GitHub at all, indicate that in the advisory and we will arrange
an alternative communication channel.

### Response time

We aim to:

* **Acknowledge** every report within **48 hours** of submission.
* **Triage** and assign a severity within **5 business days**.
* **Patch and release** a fix for issues rated critical within **14 days** of
  acknowledgement. High severity issues are targeted for a fix within 30
  days. Lower severity issues are scheduled into the regular release cadence.

If we are unable to meet these targets for a specific report, we will
communicate that directly to the reporter with reasoning and a revised
timeline.

## Scope

### In scope

* Vulnerabilities in the detection logic that cause the tool to produce
  incorrect results in a way that could mislead an operator (for example,
  false negatives on documented techniques, or rules that crash on
  legitimate input).
* Vulnerabilities in policy enumeration or report generation that could
  leak information beyond the target principal (for example, inadvertently
  including credentials or unrelated account data in output).
* Vulnerabilities in dependencies that materially affect this project.
* Code injection, deserialization, path traversal, or template injection
  issues in any code path within this repository.
* Logic errors in the Sigma rules under `detections/sigma/` that could be
  trivially evaded.

### Read-only by design

This tool is **read-only by default**. It exclusively calls AWS IAM `Get*`,
`List*`, and `sts:GetCallerIdentity` APIs and never modifies AWS resources.
A finding that the tool performs any state-changing AWS API call without
explicit user instruction is in scope and should be reported.

### Out of scope

* Social engineering of maintainers, contributors, or users.
* Physical attacks against systems that run this tool.
* Denial of service attacks against project infrastructure.
* Vulnerabilities that require an attacker to already control the user's
  workstation, AWS credentials, or shell environment.
* Findings against AWS itself. Those should be reported to AWS Security at
  [aws-security@amazon.com](mailto:aws-security@amazon.com) under the AWS
  Vulnerability Reporting program.
* Reports based solely on output from automated scanners without
  demonstrated impact.

## Responsible Disclosure Policy

We practice coordinated disclosure:

1. The reporter submits a private advisory as described above.
2. We acknowledge, triage, and develop a fix in a private branch.
3. We coordinate a release date with the reporter.
4. We publish a patched release and a public security advisory on the same
   day. The advisory describes the issue, affected versions, and the fix.
5. The reporter receives credit in the project changelog and the published
   advisory, unless they request to remain anonymous.

We ask that reporters do not publicly disclose details of a vulnerability
until a fix has been released and the advisory is published. In return, we
commit to working in good faith to ship the fix promptly and to credit
reporters who follow this process.

If a reported issue is also present in third party dependencies, we will
coordinate with the upstream maintainers and align our disclosure with
theirs.

## Legal

This project is intended **for authorized use only**.

Users are solely responsible for ensuring that they have explicit written
permission to analyze the AWS environment they target. Running this tool
against an AWS account that you do not own or have not been authorized to
assess may violate the AWS Acceptable Use Policy, the Computer Fraud and
Abuse Act, and equivalent laws in other jurisdictions.

The maintainers and contributors of `aws-iam-privesc-finder` accept no
liability for misuse of this software. The tool is provided as is, without
warranty of any kind, as set out in the [LICENSE](LICENSE) file.

Good faith security research conducted within this scope and in accordance
with the responsible disclosure policy above will not be pursued by the
maintainers.
