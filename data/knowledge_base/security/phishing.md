# Phishing

## Purpose

Phishing is a form of electronically delivered social engineering used to influence victims into taking an action that can support unauthorized access, execution, credential theft, or another malicious outcome.

MITRE ATT&CK identifies Phishing as technique T1566 under Initial Access.

## Common Phishing Forms

MITRE ATT&CK currently identifies these phishing sub-techniques:

- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service
- T1566.004 — Spearphishing Voice

## Common Indicators

Potential indicators include:

- Suspicious sender address
- Sender-domain mismatch
- Unexpected message
- Urgent or unusual request
- Credential request
- Suspicious URL
- Unexpected attachment
- Look-alike domain
- Spoofed identity
- Unusual reply-to address

These characteristics should be evaluated in context.

## Evidence to Collect

Useful evidence includes:

- Original message
- Email headers
- Sender and reply-to addresses
- Recipient
- URLs
- Attachments
- Attachment hashes
- Mail gateway logs
- URL analysis or reputation results
- User interaction records
- Browser activity
- Endpoint telemetry
- Authentication logs

## Investigation Approach

### 1. Analyze the Message

Determine whether the sender, content, links, attachments, and request are consistent with legitimate communication.

### 2. Extract Indicators

Potential IOCs include:

- Email addresses
- Domains
- URLs
- IP addresses
- Attachment names
- File hashes

### 3. Determine User Interaction

Establish whether the recipient:

- Opened the message
- Clicked a link
- Opened an attachment
- Entered credentials
- Executed a downloaded file
- Performed another relevant action

### 4. Investigate Follow-on Activity

If interaction occurred, correlate:

- Authentication events
- Endpoint activity
- Process creation
- Network connections
- Downloads
- Account changes

## Important Principle

Receiving a phishing message does not prove that the recipient was compromised.

The investigation should distinguish:

- Suspicious message
- Likely phishing
- Confirmed malicious content
- User interaction
- Evidence of compromise

## Related MITRE ATT&CK Concepts

- T1566 — Phishing
- T1204.001 — User Execution: Malicious Link
- T1204.002 — User Execution: Malicious File

## Sources

- MITRE ATT&CK — Phishing (T1566)
- MITRE ATT&CK — User Execution (T1204)
- NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations
