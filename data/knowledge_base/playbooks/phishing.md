# Phishing Investigation Playbook

## Objective

Determine whether a suspicious message represents a phishing attempt, identify relevant indicators, determine whether a user interacted with the message, and assess whether additional investigation is required.

## When to Use

Use this playbook when an incident involves:

- A suspicious email or message
- A suspicious link
- An unexpected attachment
- Credential-harvesting behavior
- Impersonation of a person or organization
- A user reporting a potentially malicious message

## Initial Evidence

Prioritize collecting:

- Original message content
- Email headers
- Sender address
- Reply-to address
- Recipient information
- URLs
- Attachments
- Message timestamps
- Mail gateway or delivery logs
- User interaction information
- Relevant endpoint or browser logs

## Investigation Steps

### 1. Analyze the message

Review sender identity, sender domain, reply-to address, subject, message content, urgency or social-engineering indicators, and requests for credentials, payments, or sensitive information.

### 2. Extract indicators

Identify potential IOCs such as sender email addresses, sender domains, URLs, domains, IP addresses, attachment filenames, and file hashes.

Only record an IOC when it can be tied to the available evidence.

### 3. Analyze URLs and attachments

Determine the destination domain, URL structure, redirect behavior when available, attachment type, attachment hash when available, and whether the destination or file is known to be suspicious.

Do not treat the presence of a URL or attachment alone as proof of maliciousness.

### 4. Determine user interaction

Establish whether the recipient opened the message, clicked a link, opened an attachment, submitted credentials, executed a downloaded file, or performed another relevant action.

### 5. Investigate downstream activity

If the user interacted with the message, look for suspicious authentication, new processes, browser activity, downloads, endpoint alerts, account changes, and network connections to suspicious destinations.

### 6. Identify related incidents

Determine whether the same sender, domain, URL, attachment, hash, or IP address appears in other reported incidents.

### 7. Identify missing evidence

Examples include original email headers, URL reputation information, attachment hash, endpoint telemetry, browser history, authentication logs, and evidence of credential submission.

## Expected Outputs

The investigation should attempt to establish:

- Incident classification
- Severity
- Relevant IOCs
- Whether the message is suspicious
- Whether the user interacted with it
- Evidence-backed findings
- Missing evidence
- Recommended next investigation steps
- Confidence level

## Important Investigation Principle

A suspicious message does not automatically establish that a user was compromised.

Distinguish between suspicious message, confirmed malicious content, user interaction, and confirmed account or endpoint compromise.
