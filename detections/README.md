# Detections

Sigma detection rules for the IAM privilege escalation techniques covered by
`aws-iam-privesc-finder`. These rules read CloudTrail (or any SIEM that
normalizes CloudTrail events) and alert when a known escalation API call is
observed in production.

## Pairing static analysis with runtime detection

The Python tool tells you *which* identities **could** escalate.
Sigma rules tell you *when* an identity actually **does** escalate.
Use both: harden against the static finding, alert on the runtime signal.

## Files

- [`sigma/iam_privesc_techniques.yml`](sigma/iam_privesc_techniques.yml) — multi-rule file covering the highest-signal techniques.

## Conversion

Convert to your SIEM's native query language with [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
sigma convert -t splunk -p cloudtrail detections/sigma/iam_privesc_techniques.yml
sigma convert -t kusto detections/sigma/iam_privesc_techniques.yml
```

## Tested log source

```yaml
logsource:
  product: aws
  service: cloudtrail
```

## Field reference

CloudTrail field shorthand used in these rules:

| Sigma field          | CloudTrail field path                    |
| -------------------- | ---------------------------------------- |
| `eventSource`        | `eventSource`                            |
| `eventName`          | `eventName`                              |
| `userIdentity.type`  | `userIdentity.type`                      |
| `userIdentity.arn`   | `userIdentity.arn`                       |
| `userIdentity.userName` | `userIdentity.userName`               |
| `requestParameters.userName` | `requestParameters.userName`     |
| `requestParameters.policyArn` | `requestParameters.policyArn`   |
| `errorCode`          | `errorCode` (only set on failure)        |
