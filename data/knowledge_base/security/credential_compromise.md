# Credential Compromise

## Purpose

Credential compromise occurs when an unauthorized party obtains or uses authentication credentials, tokens, keys, or other authentication material to gain access to resources.

For this project, the investigation agent uses this knowledge to reason about suspicious authentication and determine what evidence is needed to assess possible compromise.

## Common Causes and Indicators

Potential causes or indicators include:

- Password guessing or brute force
- Credential phishing
- Credential theft
- Credential dumping
- Reuse of compromised credentials
- Suspicious use of valid accounts
- Authentication from unusual locations or devices
- Unusual activity after successful authentication

These are indicators or possible mechanisms, not automatic proof of compromise.

## Common Evidence

Useful evidence includes:

- Authentication logs
- Failed and successful login events
- Source IP addresses
- Device information
- Authentication method
- Account privilege information
- Session activity
- Endpoint telemetry
- Commands executed after login
- File and application activity
- Network activity

## Investigation Approach

### 1. Establish the Account

Identify the affected account and determine:

- Account type
- Privilege level
- Normal usage pattern
- Systems and services accessible to it

### 2. Establish the Authentication Pattern

Correlate authentication events by:

- Account
- Source
- Time
- Authentication method
- Destination

Look for repeated failures, unusual sources, or successful authentication following suspicious activity.

### 3. Investigate Post-Authentication Activity

A successful login does not establish malicious activity.

Review activity after authentication for:

- Commands
- File access
- Configuration changes
- Privilege changes
- New accounts
- Lateral movement
- Data access or transfer

### 4. Assess Scope

Search for the same account, source IP, device, or related indicators across other systems.

## MITRE ATT&CK Relationships

Credential compromise may relate to:

- T1078 — Valid Accounts
- T1110 — Brute Force
- T1003 — OS Credential Dumping
- T1552 — Unsecured Credentials
- TA0006 — Credential Access

MITRE describes Credential Access as activity intended to obtain account names, passwords, or other credentials.

## Investigation Questions

- Was credential material actually obtained?
- Was the account used by an unauthorized party?
- Was the authentication source unusual?
- What happened after successful authentication?
- Was privilege escalation attempted?
- Was lateral movement observed?
- Were other accounts or systems affected?

## Important Principle

Do not infer credential compromise solely from an unusual login.

A finding should identify the evidence supporting the assessment and clearly distinguish confirmed facts from hypotheses.

## Sources

- MITRE ATT&CK — Credential Access (TA0006)
- MITRE ATT&CK — Valid Accounts (T1078)
- MITRE ATT&CK — Brute Force (T1110)
- MITRE ATT&CK — Unsecured Credentials (T1552)
- NIST SP 800-63B — Digital Identity Guidelines
