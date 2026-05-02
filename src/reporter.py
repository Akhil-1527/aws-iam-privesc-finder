"""Report generation: Markdown (Jinja2) and JSON outputs."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Iterable

from jinja2 import Environment, BaseLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from .analyzer import Finding, RiskLevel
from .enumerator import PrincipalPolicySet


_RISK_COLORS = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "bold dark_orange",
    RiskLevel.MEDIUM: "bold yellow",
}


_MD_TEMPLATE = """# AWS IAM Privesc Finder Report

- **Target ARN:** `{{ target_arn }}`
- **Principal Type:** {{ principal_type }}
- **Account:** {{ account_id }}
- **Generated:** {{ timestamp }}
- **Policies Examined:** {{ policy_count }}
- **Findings:** {{ findings|length }}

## Executive Summary

{% if findings|length == 0 -%}
No privilege escalation paths were detected for this principal under the
techniques currently implemented. Review the *Limitations* section before
treating this as a clean bill of health.
{%- else -%}
**{{ critical_count }} critical**, **{{ high_count }} high**, and
**{{ medium_count }} medium** escalation path(s) were identified. The
highest-risk finding is **{{ top_finding }}**. Address critical findings first
— each one represents a path to full account control.
{%- endif %}

## Findings Overview

| # | Risk | Technique | MITRE | Matched Permissions |
| - | ---- | --------- | ----- | ------------------- |
{% for f in findings -%}
| {{ loop.index }} | {{ f.risk_level }} | {{ f.technique_name }} | {{ f.mitre_attack_ref }} | `{{ f.matched_permissions|join(', ') }}` |
{% endfor %}

## Detailed Findings

{% for f in findings %}
### {{ loop.index }}. {{ f.technique_name }} — {{ f.risk_level }}

**MITRE ATT&CK:** `{{ f.mitre_attack_ref }}`

**Description**

{{ f.description }}

**Required Permissions**

{% for p in f.required_permissions -%}
- `{{ p }}`
{% endfor %}

**Matched Permissions in Target Policies**

{% for p in f.matched_permissions -%}
- `{{ p }}`
{% endfor %}

**Remediation**

{{ f.remediation }}

{% if f.extra %}
**Additional Context**

```json
{{ f.extra | tojson(indent=2) }}
```
{% endif %}

---
{% endfor %}

## Limitations

This tool inspects identity-based policies attached to the target principal
(plus its groups, for users). It does *not* currently evaluate:

- Resource-based policies (e.g. S3 bucket policies, KMS key policies)
- Service Control Policies (SCPs) at the org/OU level
- Permission Boundaries
- Session policies passed at AssumeRole time
- Condition keys (`aws:RequestTag`, `aws:SourceIp`, MFA, etc.)

A "no findings" result means *no statically-detectable identity-policy path*,
not "the principal is safe under all conditions". Pair this report with manual
review and live runtime detection (see `detections/sigma/`).

## Disclaimer

For authorized security assessments only. Do not run against AWS accounts
you do not own or have explicit written permission to test.
"""


def _jinja_env() -> Environment:
    return Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape(disabled_extensions=("md", "txt"), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_markdown(
    policy_set: PrincipalPolicySet, findings: Iterable[Finding]
) -> str:
    """Render the full Markdown report."""
    findings_list = list(findings)
    critical_count = sum(1 for f in findings_list if f.risk_level == RiskLevel.CRITICAL)
    high_count = sum(1 for f in findings_list if f.risk_level == RiskLevel.HIGH)
    medium_count = sum(1 for f in findings_list if f.risk_level == RiskLevel.MEDIUM)
    top = findings_list[0].technique_name if findings_list else "n/a"

    env = _jinja_env()
    template = env.from_string(_MD_TEMPLATE)
    return template.render(
        target_arn=policy_set.principal_arn,
        principal_type=policy_set.principal_type,
        account_id=policy_set.account_id,
        timestamp=_now_iso(),
        policy_count=len(policy_set.policies),
        findings=[_finding_for_template(f) for f in findings_list],
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        top_finding=top,
    )


def _finding_for_template(finding: Finding) -> dict:
    """Convert a Finding to a plain dict (Jinja-friendly)."""
    data = finding.to_dict()
    data["risk_level"] = finding.risk_level.value
    return data


def render_json(
    policy_set: PrincipalPolicySet, findings: Iterable[Finding]
) -> str:
    """Render a JSON report (string)."""
    findings_list = list(findings)
    payload = {
        "schema_version": "1.0",
        "generated_at": _now_iso(),
        "target": {
            "arn": policy_set.principal_arn,
            "type": policy_set.principal_type,
            "name": policy_set.principal_name,
            "account_id": policy_set.account_id,
        },
        "policies_examined": [
            {"name": p.name, "source": p.source, "arn": p.arn}
            for p in policy_set.policies
        ],
        "summary": {
            "total": len(findings_list),
            "critical": sum(
                1 for f in findings_list if f.risk_level == RiskLevel.CRITICAL
            ),
            "high": sum(1 for f in findings_list if f.risk_level == RiskLevel.HIGH),
            "medium": sum(
                1 for f in findings_list if f.risk_level == RiskLevel.MEDIUM
            ),
        },
        "findings": [f.to_dict() for f in findings_list],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def print_console_summary(
    policy_set: PrincipalPolicySet,
    findings: Iterable[Finding],
    console: Console | None = None,
) -> None:
    """Render a Rich-formatted summary to the terminal."""
    console = console or Console()
    findings_list = list(findings)

    critical = sum(1 for f in findings_list if f.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for f in findings_list if f.risk_level == RiskLevel.HIGH)
    medium = sum(1 for f in findings_list if f.risk_level == RiskLevel.MEDIUM)

    header_lines = [
        "[bold cyan]AWS IAM Privesc Finder v1.0[/bold cyan]",
        f"Target: [bold]{policy_set.principal_arn}[/bold]",
        f"Policies examined: {len(policy_set.policies)}",
    ]
    console.rule("[bold cyan]Privesc Finder[/bold cyan]")
    for line in header_lines:
        console.print(line)
    console.rule()

    if not findings_list:
        console.print("[bold green]No escalation paths detected.[/bold green]")
        return

    console.print(
        f"[bold]FINDINGS[/bold] "
        f"([red]{critical} critical[/red], "
        f"[dark_orange]{high} high[/dark_orange], "
        f"[yellow]{medium} medium[/yellow])"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Risk", width=10)
    table.add_column("Technique")
    table.add_column("MITRE", width=10)
    table.add_column("Matched Permissions")

    for idx, finding in enumerate(findings_list, start=1):
        color = _RISK_COLORS[finding.risk_level]
        table.add_row(
            str(idx),
            f"[{color}]{finding.risk_level.value}[/{color}]",
            finding.technique_name,
            finding.mitre_attack_ref,
            ", ".join(finding.matched_permissions),
        )

    console.print(table)

    for idx, finding in enumerate(findings_list, start=1):
        color = _RISK_COLORS[finding.risk_level]
        console.print()
        console.print(
            f"[{color}][{finding.risk_level.value}][/{color}] "
            f"[bold]{finding.technique_name}[/bold]"
        )
        console.print(f"  Permissions matched: {', '.join(finding.matched_permissions)}")
        console.print(f"  Remediation: {finding.remediation}")
        console.print(f"  MITRE: {finding.mitre_attack_ref}")
