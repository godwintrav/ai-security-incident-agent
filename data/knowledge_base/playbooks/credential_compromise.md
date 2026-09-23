# Credential Compromise Investigation Playbook

## Objective

Determine whether an account credential may have been compromised, identify the affected account and supporting indicators, assess the scope of suspicious activity, and identify evidence that is still required.

## When to Use

Use this playbook when an incident contains one or more signs of suspicious authentication, including:

- Repeated failed authentication attempts followed by a successful login
- Authentication from an unusual or previously unseen source
- Suspicious use of a privileged account
- Authentication at an unusual time
- Evidence that valid credentials may have been used by an unauthorized person
- Unexpected changes to account or authentication configuration

## Initial Evidence

Prioritize collecting:

- Authentication logs
- Successful and failed login events
- Source IP addresses
- Destination hostnames or systems
- Account or username information
- Authentication timestamps
- Authentication method
- Account privilege information
- Recent account activity
- Relevant endpoint or application logs

## Investigation Steps

### 1. Identify the affected account

Determine the username or account identifier, account type, privilege level, and systems the account can access.

### 2. Analyze authentication activity

Review failed and successful authentication attempts, authentication methods, source IP addresses, timestamps, and repeated or unusual patterns.

Determine whether suspicious failed attempts were followed by a successful authentication.

### 3. Identify suspicious source indicators

Look for previously unseen source IPs, unusual network locations, multiple accounts accessed from the same suspicious source, and authentication patterns inconsistent with normal activity.

Record relevant IP addresses and other indicators as IOCs when supported by evidence.

### 4. Review post-authentication activity

After a suspicious successful authentication, determine what happened next.

Look for:

- Commands executed
- Files accessed or modified
- Privilege changes
- New accounts
- Configuration changes
- Lateral movement
- Data access or transfer
- Persistence mechanisms

### 5. Assess credential-compromise likelihood

Consider the complete evidence rather than relying on a single indicator.

Evidence supporting possible compromise may include a suspicious authentication pattern, successful login after repeated failures, unusual source, unexpected privilege use, or suspicious activity immediately after authentication.

### 6. Identify missing evidence

If the investigation cannot establish scope or impact, record the missing evidence.

Examples include post-authentication activity, account privilege information, historical authentication logs, endpoint activity, network activity, and source IP reputation or historical occurrence.

## Expected Outputs

The investigation should attempt to establish:

- Incident classification
- Severity
- Affected account
- Affected systems
- Relevant IOCs
- Evidence-backed findings
- Missing evidence
- Recommended next investigation steps
- Confidence level

## Important Investigation Principle

A suspicious authentication pattern is evidence of possible credential compromise, not proof by itself that credentials were compromised.

Separate observed evidence, reasonable assessment, and confirmed facts.

Do not claim that a vulnerability, IP address, or authentication event caused the incident unless the available evidence supports that conclusion.
