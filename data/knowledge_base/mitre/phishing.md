# MITRE ATT&CK — Phishing

## Purpose

This document contains MITRE ATT&CK techniques relevant to investigating phishing incidents.

Phishing is commonly associated with Initial Access, but phishing activity may also lead to execution, credential theft, or other follow-on activity.

---

## T1566 — Phishing

### Description

Adversaries may send phishing messages to gain access to victim systems, accounts, or information.

Phishing can use malicious attachments, links, services, or voice communication.

### Investigation Relevance

Consider this technique when an incident involves:

- Suspicious email
- Suspicious messaging
- Credential-harvesting links
- Malicious attachments
- Impersonation
- Social engineering

### Potential Evidence

- Original message
- Email headers
- Sender address
- Reply-to address
- URLs
- Attachments
- Mail gateway logs
- Recipient information
- User interaction

---

## T1566.001 — Spearphishing Attachment

### Description

Adversaries may send malicious files as email attachments to targeted victims.

### Investigation Relevance

Look for:

- Unexpected attachments
- Executable or script files
- Malicious documents
- Archive files
- Attachments associated with suspicious senders

### Potential Evidence

- Attachment filename
- File type
- File hash
- Email headers
- Endpoint execution events
- Process creation events

### Potential IOCs

- File hashes
- Filenames
- Sender email addresses
- Sender domains

---

## T1566.002 — Spearphishing Link

### Description

Adversaries may send links designed to direct victims to malicious or credential-harvesting resources.

### Investigation Relevance

Look for:

- Suspicious URLs
- Look-alike domains
- Credential-harvesting pages
- Unexpected links
- Redirect chains

### Potential Evidence

- URL
- Domain
- DNS activity
- Proxy logs
- Browser history
- Authentication activity

### Potential IOCs

- URLs
- Domains
- IP addresses
- Sender email addresses

---

## T1566.003 — Spearphishing via Service

### Description

Adversaries may use third-party services or messaging platforms to deliver targeted phishing content.

### Investigation Relevance

Consider this technique when suspicious content is delivered through a legitimate external service rather than traditional email.

### Potential Evidence

- Service or platform
- Sender identity
- Message content
- Links
- Attachments
- Account information

---

## T1566.004 — Spearphishing Voice

### Description

Adversaries may use voice communication to deliver phishing or social-engineering attacks.

### Investigation Relevance

Consider this technique when a suspicious phone or voice interaction attempts to obtain credentials, sensitive information, or access.

### Potential Evidence

- Caller information
- Call records
- Reported interaction
- Follow-on authentication activity
- Account changes

---

## T1204 — User Execution

### Description

Adversaries may rely on victims to execute malicious content or interact with malicious links.

### Relevant Sub-techniques

- T1204.001 — Malicious Link
- T1204.002 — Malicious File

### Investigation Relevance

Determine whether the victim:

- Clicked a link
- Opened an attachment
- Executed a file
- Submitted credentials
- Downloaded content

### Potential Evidence

- Browser logs
- Endpoint telemetry
- Process creation
- File creation
- Authentication events
- Proxy logs

---

## Investigation Guidance

Receiving a phishing message does not prove compromise.

The investigation should distinguish:

1. Suspicious message
2. Likely phishing
3. Confirmed malicious content
4. User interaction
5. Evidence of credential or endpoint compromise

## Related Tactics

- Initial Access
- Execution
- Credential Access

## Sources

MITRE ATT&CK Enterprise techniques:

- T1566 — Phishing
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service
- T1566.004 — Spearphishing Voice
- T1204 — User Execution
