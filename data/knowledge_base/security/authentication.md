# Authentication

## Purpose

Authentication is the process of establishing that a user, service, device, or other entity is the legitimate owner of an identity or authenticator.

For this project, authentication knowledge helps the investigation agent interpret login events, identify suspicious authentication patterns, and determine what additional evidence should be collected.

## Authentication Factors

Common authentication factors include:

- Something you know — for example, a password or PIN
- Something you have — for example, a hardware security key or authenticator device
- Something you are — for example, a biometric characteristic

Authentication systems may combine multiple factors.

## Authentication Events

Useful authentication evidence can include:

- Account or username
- Authentication result
- Timestamp
- Source IP address
- Destination system
- Authentication method
- Device information
- Session information
- Failure reason
- Geographic or network context when available

A single authentication event usually provides limited context. Investigation often requires correlating multiple events.

## Failed and Successful Authentication

Repeated failed authentication attempts can indicate password guessing or other suspicious activity, but failed attempts can also result from legitimate user error or automated systems.

A successful authentication after a suspicious sequence of failures can increase the importance of the investigation.

The agent should therefore consider:

1. Number of failed attempts
2. Time window
3. Source IP or source device
4. Account targeted
5. Successful authentication
6. Activity following successful authentication

## Valid Accounts

An attacker may use legitimate credentials to access systems. MITRE ATT&CK describes this as Valid Accounts (T1078).

Using valid credentials can make activity harder to distinguish from legitimate access because the authentication itself may succeed normally.

## Authentication Investigation Questions

The investigation should consider:

- Which account was involved?
- Was authentication successful?
- How many failures occurred?
- Were failures followed by success?
- What source IP or device was used?
- Is the source unusual for this account?
- What authentication method was used?
- What happened after authentication?
- Does the account have elevated privileges?
- Are similar authentication events present elsewhere?

## Important Principle

Do not equate an unusual login with confirmed compromise.

The investigation should distinguish:

- Observed authentication event
- Suspicious authentication pattern
- Evidence supporting possible credential compromise
- Evidence confirming compromise

## Related MITRE ATT&CK Concepts

- T1078 — Valid Accounts
- T1110 — Brute Force
- TA0006 — Credential Access

## Sources

- MITRE ATT&CK — Valid Accounts (T1078)
- MITRE ATT&CK — Credential Access (TA0006)
- MITRE ATT&CK — Brute Force (T1110)
- NIST SP 800-63B — Digital Identity Guidelines: Authentication and Authenticator Management
