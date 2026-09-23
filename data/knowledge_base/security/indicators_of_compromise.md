# Indicators of Compromise

## Purpose

An Indicator of Compromise (IOC) is an observable artifact that may provide evidence of malicious or suspicious activity.

For this project, IOCs are extracted from evidence and associated with the evidence that supports them.

## IOC Types

The initial project schema supports these IOC types:

- `ip_address`
- `domain`
- `url`
- `email`
- `file_hash`
- `file_name`
- `file_path`
- `process`
- `username`
- `hostname`

The list may expand later.

## Examples

### IP Address

```text
185.10.10.10
```

Potentially relevant when it appears as the source or destination of suspicious activity.

### Domain

```text
example-suspicious-domain.test
```

Potentially relevant when associated with suspicious email, network communication, or malware behavior.

### URL

```text
https://example.test/login
```

Potentially relevant in phishing or suspicious network activity.

### File Hash

```text
<sha256-hash>
```

Useful for identifying the same file across systems.

### Email

```text
sender@example.test
```

Potentially relevant in phishing investigations.

## IOC Confidence

An IOC should have confidence based on the evidence supporting its relevance.

For example:

- Low — observed but weak context
- Medium — supported by multiple relevant observations
- High — strongly supported by correlated evidence

Confidence should describe confidence in the IOC's relevance, not automatically mean that the IOC is malicious.

## Evidence Association

Every IOC in the investigation state should reference the evidence that caused it to be extracted.

Example:

```json
{
  "id": "ioc_001",
  "type": "ip_address",
  "value": "185.10.10.10",
  "evidence_id": "evidence_003",
  "confidence": 0.91
}
```

This makes the report traceable.

## IOC Lifecycle

The expected flow is:

```text
Raw Evidence
    ↓
Tool or Model Analysis
    ↓
Candidate IOC
    ↓
Evidence Association
    ↓
Investigation State
    ↓
Final Report
```

The investigation agent/state manager is responsible for incorporating validated IOC information into the investigation state.

The fine-tuned LLM may identify candidate IOCs in its structured analysis, while deterministic application logic should validate the expected schema and associate each IOC with supporting evidence.

## Important Principle

An IOC is not automatically proof of compromise.

For example:

```text
Observed IP address
        ≠
Confirmed malicious IP
```

The investigation should preserve the distinction between:

- Observed artifact
- Suspicious indicator
- Threat-intelligence-supported indicator
- Confirmed malicious indicator

## IOC Extraction Sources

IOCs may come from:

- User-provided incident descriptions
- Raw logs
- `analyze_logs`
- Other investigation tools
- Fine-tuned model analysis
- External intelligence tools

The exact extraction mechanism depends on the evidence and tool being used.

## Sources

- NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations
- MITRE ATT&CK — Detection Strategies and technique documentation
