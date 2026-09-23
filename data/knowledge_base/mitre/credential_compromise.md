# MITRE ATT&CK — Credential Compromise

## Purpose

This document contains MITRE ATT&CK techniques relevant to investigating suspected credential compromise.

Use these techniques as contextual knowledge during investigation. A technique being relevant does not prove that an adversary used it in a particular incident.

---

## T1078 — Valid Accounts

### Description

Adversaries may obtain and abuse valid accounts to gain access to systems or services. Because the credentials may be legitimate, authentication can appear normal.

### Investigation Relevance

Consider this technique when:

- A legitimate account is used from an unusual source.
- Authentication occurs at an unusual time.
- A previously unseen device or location accesses the account.
- A privileged account is used unexpectedly.
- Suspicious activity follows a successful authentication.

### Potential Evidence

- Authentication logs
- Username
- Source IP
- Source device
- Authentication timestamp
- Authentication method
- Account privilege information
- Post-authentication activity

### Potential IOCs

- Username
- Source IP address
- Hostname
- Device identifier

---

## T1110 — Brute Force

### Description

Adversaries may use repeated attempts to authenticate to an account or system by guessing or trying credentials.

### Relevant Sub-techniques

- T1110.001 — Password Guessing
- T1110.002 — Password Cracking
- T1110.003 — Password Spraying
- T1110.004 — Credential Stuffing

### Investigation Relevance

Consider this technique when logs show:

- Repeated authentication failures
- Multiple attempts against a single account
- Attempts against many accounts
- Authentication failures from a common source
- A successful authentication after repeated failures

### Potential Evidence

- Number of failed attempts
- Number of targeted accounts
- Source IP addresses
- Time window
- Authentication results
- Successful authentication following failures

### Potential IOCs

- Source IP addresses
- Target usernames
- Hostnames

---

## T1003 — OS Credential Dumping

### Description

Adversaries may attempt to obtain credentials from operating-system components or processes.

### Investigation Relevance

Consider this technique when endpoint evidence indicates suspicious access to credential stores, credential-related processes, or tools commonly associated with credential dumping.

### Potential Evidence

- Process execution
- Command lines
- Process trees
- Access to credential stores
- Security logs
- Endpoint detection alerts
- Suspicious tools or binaries

### Potential IOCs

- Process names
- File hashes
- File paths
- Command lines
- Hostnames

---

## T1552 — Unsecured Credentials

### Description

Adversaries may search for credentials stored in insecure locations, such as files, configuration data, scripts, or other accessible resources.

### Investigation Relevance

Consider this technique when evidence suggests an attacker searched for or accessed credentials stored in insecure locations.

### Potential Evidence

- File access
- Command execution
- Configuration files
- Scripts
- Environment variables
- Endpoint telemetry

### Potential IOCs

- File paths
- Filenames
- Process names
- Usernames
- Hostnames

---

## Investigation Guidance

These techniques can help classify and investigate authentication-related behavior, but the investigation should distinguish:

1. Observed authentication activity
2. Suspicious authentication activity
3. Evidence supporting possible credential compromise
4. Evidence confirming credential compromise

Do not classify an incident as credential compromise solely because a login came from an unfamiliar location.

## Related Tactics

- Initial Access
- Credential Access
- Persistence
- Privilege Escalation
- Defense Evasion

## Sources

MITRE ATT&CK Enterprise techniques:

- T1078 — Valid Accounts
- T1110 — Brute Force
- T1003 — OS Credential Dumping
- T1552 — Unsecured Credentials
