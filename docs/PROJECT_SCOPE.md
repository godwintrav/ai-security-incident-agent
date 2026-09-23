# AI Security Incident Investigation Agent — Project Scope

## 1. Project Overview

The AI Security Incident Investigation Agent is an AI-powered security investigation assistant that helps security engineers investigate potential security incidents.

A security engineer provides an incident description and available evidence such as logs. The system uses an investigation agent, security knowledge retrieval, investigation playbooks, external investigation tools, and a fine-tuned language model to analyze the incident.

The agent can identify gaps in the available evidence and perform additional investigation steps before producing a final evidence-backed incident report.

The system is designed as a **human-in-the-loop investigation assistant**, not an autonomous security response system.

---

## 2. Problem Being Solved

Security investigations often require engineers to:

- Review large amounts of logs.
- Identify suspicious activity.
- Determine what type of incident occurred.
- Extract indicators of compromise.
- Research relevant security information.
- Follow appropriate investigation procedures.
- Determine what evidence is still missing.
- Produce an incident report.

This process can be time-consuming and inconsistent.

The goal of this project is to build an AI system that can assist with these investigation tasks while keeping the investigation grounded in available evidence.

The system should not simply generate a report from the initial prompt.

Instead, it should be capable of:

```text
Incident
    ↓
Investigate
    ↓
Collect Evidence
    ↓
Analyze Evidence
    ↓
Identify Evidence Gaps
    ↓
Investigate Further
    ↓
Evaluate Investigation
    ↓
Final Report
```

---

## 3. Project Goals

The V1 system should demonstrate the following capabilities:

1. Accept a structured security incident and supporting evidence.
2. Analyze security logs and other evidence.
3. Classify the primary incident type.
4. Determine incident severity.
5. Extract indicators of compromise (IOCs).
6. Retrieve relevant security knowledge using semantic RAG.
7. Retrieve the appropriate incident investigation playbook.
8. Search for potentially relevant CVEs when applicable.
9. Use a fine-tuned LLM for specialized incident analysis.
10. Maintain investigation state across multiple investigation steps.
11. Identify missing evidence.
12. Allow the investigation agent to obtain additional evidence.
13. Re-analyze the incident when new evidence is discovered.
14. Evaluate the quality and completeness of the investigation.
15. Produce a structured, evidence-backed final report.

---

## 4. V1 Incident Types

The first version will focus on six incident types.

### 4.1 Brute Force

Repeated attempts to guess or obtain authentication credentials.

Examples:

- Repeated failed SSH logins.
- Repeated failed web authentication attempts.
- Multiple authentication attempts against an account.

### 4.2 Credential Compromise

Evidence that valid credentials or an account may have been compromised or misused.

Examples:

- Suspicious successful login.
- Login from an unusual location or IP.
- Valid credentials used after suspicious authentication activity.
- Account activity inconsistent with previous behavior.

### 4.3 Malware / Suspicious File

Evidence of potentially malicious software, files, or processes.

Examples:

- Suspicious executable.
- Unexpected process.
- Known malware hash.
- Suspicious file execution.

### 4.4 Phishing

Malicious communication intended to trick a user into revealing information or performing an unsafe action.

Examples:

- Suspicious email.
- Malicious URL.
- Credential harvesting page.
- Suspicious attachment.

### 4.5 Privilege Escalation

Evidence that an account or process obtained higher privileges without authorization.

Examples:

- Unexpected administrator privileges.
- Suspicious use of `sudo`.
- Unauthorized role changes.
- Exploitation of a privilege boundary.

### 4.6 Data Exfiltration

Evidence of unauthorized or suspicious transfer of data outside the environment.

Examples:

- Large outbound data transfer.
- Sensitive files transferred externally.
- Suspicious uploads.
- Unexpected connections to external infrastructure.

---

## 5. Incident Classification

The system will assign one **primary incident type** during V1.

Supported values:

```text
BRUTE_FORCE
CREDENTIAL_COMPROMISE
MALWARE
PHISHING
PRIVILEGE_ESCALATION
DATA_EXFILTRATION
```

Incident types may be related.

For example:

```text
PHISHING
    ↓
CREDENTIAL_COMPROMISE
    ↓
PRIVILEGE_ESCALATION
    ↓
DATA_EXFILTRATION
```

However, V1 classification will use a single primary incident type to simplify model training and evaluation.

Related incident types or security techniques can be added later.

---

## 6. Input Format

V1 will accept a structured JSON request.

Example:

```json
{
  "incident_description": "We detected repeated failed SSH login attempts followed by a successful login to a production server.",
  "logs": [
    {
      "timestamp": "2026-09-17T10:21:34Z",
      "source": "auth.log",
      "message": "Failed password for admin from 185.123.45.67"
    },
    {
      "timestamp": "2026-09-17T10:22:01Z",
      "source": "auth.log",
      "message": "Accepted password for admin from 185.123.45.67"
    }
  ],
  "additional_evidence": []
}
```

The initial input consists of:

- Incident description.
- Logs.
- Optional additional evidence.

The system may support additional evidence formats in future versions.

---

## 7. Incident Schema

An investigation will contain an incident object representing the case being investigated.

Conceptually:

```json
{
  "incident_id": "application-generated-id",
  "incident_description": "Repeated SSH login attempts followed by a successful login.",
  "status": "investigating",
  "incident_type": null,
  "severity": null,
  "confidence": null
}
```

### Fields

| Field | Description |
|---|---|
| `incident_id` | Unique identifier generated by the application |
| `incident_description` | Original incident description supplied by the user |
| `status` | Current investigation status |
| `incident_type` | Primary classified incident type |
| `severity` | Assigned severity level |
| `confidence` | Model confidence in the assessment |

The application, rather than the LLM, is responsible for generating identifiers.

---

## 8. Evidence Schema

Evidence represents information observed or retrieved during the investigation.

Examples include:

- Authentication logs.
- Network events.
- Process information.
- Files.
- File hashes.
- User activity.
- CVE information.
- Tool results.
- Retrieved security knowledge.

Conceptual schema:

```json
{
  "id": "application-generated-id",
  "type": "log",
  "source": "auth.log",
  "timestamp": "2026-09-17T10:21:34Z",
  "content": "Failed password for admin from 185.123.45.67",
  "relevance": "high"
}
```

Evidence identifiers are generated by the application.

The LLM does not generate or control evidence IDs.

---

## 9. Evidence vs Findings

The system must distinguish between **evidence** and **findings**.

### Evidence

What was actually observed.

Example:

```text
150 failed SSH authentication attempts were observed
from 185.123.45.67 within five minutes.
```

### Finding

What the investigation concludes from that evidence.

Example:

```text
The observed authentication activity is consistent
with a brute-force attack.
```

The evidence is the observation.

The finding is the interpretation or conclusion based on that observation.

Findings should reference the evidence that supports them.

---

## 10. Severity Levels

V1 will use four severity levels:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

### LOW

Limited impact or suspicious activity with little evidence of successful compromise.

Example:

```text
A small number of failed authentication attempts
from an unknown IP address.
```

### MEDIUM

Meaningful suspicious activity with potential security implications.

Example:

```text
A large number of failed authentication attempts
against a user account.
```

### HIGH

Evidence suggests successful compromise or significant security impact.

Example:

```text
A successful login follows suspicious authentication
activity and occurs on a production system.
```

### CRITICAL

Major confirmed or strongly supported compromise with significant impact.

Examples:

- Large-scale data exfiltration.
- Administrative account compromise.
- Widespread malware infection.
- Significant production infrastructure compromise.

The system should provide evidence/reasoning supporting the assigned severity.

---

## 11. Indicators of Compromise (IOCs)

The system will extract relevant Indicators of Compromise (IOCs) from available evidence.

V1 IOC types:

```text
IP_ADDRESS
DOMAIN
URL
FILE_HASH
FILE_NAME
EMAIL_ADDRESS
USERNAME
PROCESS
FILE_PATH
MALWARE_NAME
CVE
```

Example:

```json
{
  "id": "application-generated-id",
  "type": "IP_ADDRESS",
  "value": "185.123.45.67",
  "source_evidence_id": "application-generated-id",
  "confidence": 0.98
}
```

An IOC should not automatically be treated as proof of malicious activity.

For example, an IP address appearing in a log proves that the IP was observed. It does not necessarily prove that the IP belongs to an attacker.

---

## 12. Findings

A finding represents an important conclusion derived from evidence.

Conceptual structure:

```json
{
  "id": "application-generated-id",
  "title": "Repeated authentication attempts",
  "description": "150 failed SSH authentication attempts were observed.",
  "assessment": "The activity is consistent with a brute-force attack.",
  "confidence": 0.94,
  "evidence_ids": [
    "application-generated-evidence-id"
  ]
}
```

Each finding should contain:

- Finding title.
- Description.
- Assessment.
- Confidence.
- Supporting evidence references.

The application generates the finding identifier.

The AI generates the finding content.

---

## 13. Missing Evidence

Missing evidence represents information required to improve or complete the investigation.

The system should not simply state:

```text
"I don't know."
```

Instead, it should identify:

1. What information is missing.
2. Why that information matters.
3. How important it is.
4. Where or how it might be obtained.

Example:

```json
{
  "id": "application-generated-id",
  "description": "Commands executed after the successful SSH login.",
  "reason": "Authentication logs confirm a successful login but do not show what actions were performed afterward.",
  "priority": "high",
  "suggested_source": "shell_history"
}
```

A missing-evidence item should contain:

- Description.
- Reason.
- Priority.
- Suggested evidence source or tool.

This information can be used by the investigation agent to determine its next action.

---

## 14. Investigation State

The system will maintain state throughout the investigation.

Conceptually:

```text
Investigation State
│
├── Incident
├── Evidence
├── IOCs
├── Findings
├── Missing Evidence
├── Investigation Steps
├── Model Analyses
├── Tool Results
└── Iteration Count
```

The state allows the agent to remember what has already been discovered and avoid treating every investigation step as a completely new investigation.

Example:

```text
Iteration 1
    ↓
Initial evidence
    ↓
Analysis
    ↓
Missing evidence identified
    ↓
Iteration 2
    ↓
Additional evidence
    ↓
New analysis
    ↓
Evaluation
```

V1 will place a hard limit on investigation iterations to prevent uncontrolled agent loops.

---

## 15. Investigation Agent

The investigation agent acts as the coordinator of the investigation.

Its responsibilities include:

- Understanding the incident.
- Determining what information is needed.
- Selecting appropriate tools.
- Calling tools.
- Reviewing tool results.
- Updating investigation state.
- Determining whether additional evidence is required.
- Coordinating additional investigation.
- Passing relevant evidence to the analysis model.
- Determining when the investigation is ready for evaluation.

V1 will use a **single investigation agent** rather than multiple specialized agents.

The agent may perform planning internally, but a separate planner agent is not required.

---

## 16. Investigation Tools

The investigation agent will have four primary tools.

These tools serve different purposes and use different retrieval/processing mechanisms.

### 16.1 `analyze_log()`

#### Purpose

Analyze and structure raw security logs.

The tool can:

- Parse log entries.
- Identify authentication events.
- Identify IP addresses.
- Identify usernames.
- Identify processes.
- Identify suspicious patterns.
- Produce structured observations.

Example:

```text
Raw log
    ↓
analyze_log()
    ↓
Structured evidence
```

The goal is to prevent the language model from repeatedly processing large amounts of raw log data when structured evidence is sufficient.

### 16.2 `search_security_knowledge()`

#### Purpose

Perform semantic search against the security knowledge base.

The knowledge base may contain:

- Security concepts.
- Investigation guidance.
- MITRE ATT&CK-related information.
- Authentication/security guidance.
- Threat investigation material.
- Other approved security reference documents.

The retrieval flow is:

```text
Security Documents
        ↓
Chunking
        ↓
Embeddings
        ↓
ChromaDB
        ↓
Semantic Search
        ↓
Relevant Knowledge
        ↓
Investigation Agent
```

The agent formulates a query based on the current investigation.

Example:

```text
search_security_knowledge(
    "investigation guidance for suspicious SSH authentication followed by successful login"
)
```

This is **semantic retrieval**.

### 16.3 `get_incident_playbook()`

#### Purpose

Retrieve the investigation procedure associated with the identified incident type.

Example:

```text
get_incident_playbook("CREDENTIAL_COMPROMISE")
```

The tool returns the relevant investigation playbook.

Example:

```text
Credential Compromise Playbook

1. Verify authentication activity.
2. Identify affected accounts.
3. Review source IP addresses.
4. Review successful logins.
5. Examine activity after authentication.
6. Check privilege changes.
7. Check potential data access.
8. Record evidence gaps.
```

#### Retrieval Method

Playbook retrieval is **deterministic**, not semantic RAG.

The agent already knows the incident type:

```text
incident_type = CREDENTIAL_COMPROMISE
```

Therefore:

```text
CREDENTIAL_COMPROMISE
        ↓
get_incident_playbook()
        ↓
Credential Compromise Playbook
```

There is no need for vector similarity search to determine which playbook is appropriate.

This is intentionally different from:

```text
search_security_knowledge()
        ↓
ChromaDB
        ↓
Semantic similarity search
```

The playbook may be stored as a complete document/object and retrieved directly using the incident type.

### 16.4 `search_cve()`

#### Purpose

Search for potentially relevant Common Vulnerabilities and Exposures (CVEs).

Example:

```text
search_cve(
    product="OpenSSH",
    version="8.2"
)
```

The tool may return potentially relevant vulnerability information.

However, a returned CVE does not automatically prove that the vulnerability caused the incident.

The system must distinguish between:

```text
Potentially relevant CVE
```

and:

```text
CVE demonstrated as the cause of the incident
```

The latter requires supporting evidence.

---

## 17. Tool Selection

The investigation agent decides which tools are appropriate based on the current investigation state.

For example:

```text
Incident
   ↓
Agent
   ↓
analyze_log()
   ↓
Determine likely incident type
   ↓
get_incident_playbook()
   ↓
search_security_knowledge()
   ↓
search_cve() if relevant
```

The agent does not necessarily need to call every tool for every incident.

For example, a phishing investigation may require:

```text
analyze_log()
search_security_knowledge()
get_incident_playbook()
```

while a software vulnerability investigation may additionally require:

```text
search_cve()
```

---

## 18. Evidence Sources vs Security Knowledge

The system must clearly distinguish between investigation evidence and reference knowledge.

### Investigation Evidence

Information about the specific incident.

Examples:

- Authentication logs.
- Network events.
- Process events.
- File hashes.
- User activity.
- Tool results.

### Security Knowledge

General information used to interpret the evidence.

Examples:

- MITRE ATT&CK information.
- Security concepts.
- Investigation guidance.
- Authentication best practices.
- Threat intelligence/reference material.

The system should never present retrieved security knowledge as if it were evidence that an event occurred.

For example:

```text
Security Knowledge:
"Brute-force attacks commonly involve repeated authentication attempts."
```

does not prove:

```text
"This incident was a brute-force attack."
```

The latter requires incident-specific evidence.

---

## 19. Fine-Tuned LLM

The fine-tuned model will specialize in security incident analysis.

Its responsibilities include:

- Incident classification.
- Severity assessment.
- IOC extraction.
- Evidence interpretation.
- Finding generation.
- Identification of potentially missing evidence.
- Structured incident analysis.

The model will not be responsible for:

- Generating application IDs.
- Acting as the database.
- Directly executing investigation tools.
- Serving as the entire security knowledge base.
- Automatically taking remediation actions.

The fine-tuned model should analyze relevant evidence supplied by the investigation system rather than blindly receiving every raw tool result.

---

## 20. Structured Model Analysis

The model should return structured analysis rather than only free-form text.

Example:

```json
{
  "incident_type": "CREDENTIAL_COMPROMISE",
  "severity": "HIGH",
  "confidence": 0.82,
  "indicators": [
    {
      "type": "IP_ADDRESS",
      "value": "185.123.45.67"
    },
    {
      "type": "USERNAME",
      "value": "admin"
    }
  ],
  "findings": [
    {
      "title": "Successful login after repeated failures",
      "assessment": "The activity is consistent with possible credential compromise."
    }
  ],
  "missing_evidence": [
    {
      "description": "Commands executed after login",
      "priority": "high"
    }
  ]
}
```

The application will validate and store this output in the investigation state.

---

## 21. Iterative Investigation

The investigation should be capable of repeating the analysis process when important evidence is missing.

Example:

```text
Initial Incident
      ↓
Agent
      ↓
Analyze Logs
      ↓
Classify Incident
      ↓
Retrieve Playbook
      ↓
Retrieve Security Knowledge
      ↓
Search CVEs if applicable
      ↓
Analyze Evidence
      ↓
Missing Evidence?
      │
      ├── NO → Evaluation
      │
      └── YES
            ↓
       Agent selects tool
            ↓
       Additional Evidence
            ↓
       Analyze Again
            ↓
       Evaluation
```

The system will use a maximum investigation iteration limit.

The initial target is **2–3 investigation iterations**.

---

## 22. Evaluation

A separate evaluator will assess the investigation before the final report is accepted.

The evaluator will check areas such as:

- Incident classification.
- Severity.
- IOC extraction.
- Evidence completeness.
- Evidence-to-finding relationships.
- Groundedness.
- Citation/source correctness.
- Required playbook coverage.
- Missing evidence.
- Unsupported claims.

The evaluator is intentionally separate from the fine-tuned analysis model.

This creates a distinction between:

```text
Analyst
    ↓
"What do I think happened?"
```

and:

```text
Evaluator
    ↓
"Did the investigation meet the required criteria?"
```

---

## 23. Final Report Structure

The final report will contain:

```text
1. Investigation Overview
2. Executive Summary
3. Incident Classification
4. Severity & Confidence
5. Indicators of Compromise
6. Evidence Analyzed
7. Investigation Timeline
8. Investigation Actions
9. Key Findings
10. Security Knowledge Used
11. Playbook Coverage
12. Evidence Gaps
13. Overall Assessment
14. Recommended Next Investigation Steps
15. Sources
16. AI Evaluation
```

The report should clearly distinguish:

```text
Evidence
    ↓
Analysis
    ↓
Finding
    ↓
Assessment
```

It should avoid presenting assumptions as confirmed facts.

---

## 24. Human-in-the-Loop Design

The system is an investigation assistant.

It is not intended to autonomously:

- Block IP addresses.
- Disable user accounts.
- Delete files.
- Kill processes.
- Modify firewall rules.
- Shut down systems.
- Execute remediation commands.
- Make irreversible security decisions.

A security engineer remains responsible for decisions and actions taken based on the investigation.

---

## 25. V1 Out of Scope

The following are intentionally excluded from V1:

### Autonomous Remediation

No automatic blocking, deletion, account disabling, or infrastructure changes.

### Full SIEM Replacement

The project will not attempt to replace a complete SIEM platform.

### Real-Time Monitoring

The initial system will investigate submitted incidents rather than continuously monitor an environment.

### Multi-Agent Architecture

V1 will use one investigation agent rather than multiple specialized agents.

### Large-Scale Enterprise Ingestion

V1 will work with controlled datasets and manageable investigation inputs.

### Automatic Threat Attribution

The system will not attempt to determine the identity or nationality of an attacker.

### Guaranteed Incident Attribution

The system will distinguish between evidence-supported conclusions and uncertainty.

---

## 26. Success Criteria

The V1 project will be considered successful if it can demonstrate an end-to-end investigation where the system:

1. Receives an incident and evidence.
2. Correctly identifies the primary incident type on the evaluation dataset.
3. Produces a severity assessment.
4. Extracts relevant IOCs.
5. Retrieves relevant security knowledge through semantic RAG.
6. Retrieves the correct incident investigation playbook deterministically.
7. Searches for relevant CVEs when appropriate.
8. Uses the investigation agent to select and execute tools.
9. Produces structured analysis using the fine-tuned model.
10. Identifies meaningful missing evidence.
11. Performs an additional investigation step when necessary.
12. Evaluates its investigation using a separate evaluator.
13. Produces a final report where important findings can be traced back to supporting evidence.

Success will be measured using a dedicated evaluation/regression dataset rather than relying only on subjective inspection of individual examples.

---

## 27. Core Architecture Mental Model

The entire system can be understood as:

```text
                         User
                          │
                   Incident + Logs
                          │
                          ↓
                    ┌───────────┐
                    │  FastAPI  │
                    └─────┬─────┘
                          │
                          ↓
                 ┌─────────────────┐
                 │ Investigation   │
                 │     Agent       │
                 └────────┬────────┘
                          │
        ┌─────────────────┼──────────────────┐
        │                 │                  │
        ↓                 ↓                  ↓
 analyze_log()   search_security_     get_incident_
                 knowledge()          playbook()
        │                 │                  │
        │                 ↓                  ↓
        │             ChromaDB          Deterministic
        │             Semantic           Playbook
        │              Search             Lookup
        │                 │                  │
        └─────────────────┼──────────────────┘
                          │
                          │
                    search_cve()
                          │
                          ↓
                  Relevant Evidence
                  + Security Context
                          │
                          ↓
                  ┌─────────────────┐
                  │  Fine-Tuned LLM │
                  │ Security Analyst│
                  └────────┬────────┘
                           │
                           ↓
                  Structured Analysis
                           │
                           ↓
                  Missing Evidence?
                     /           \
                   YES            NO
                    │              │
                    ↓              ↓
                  Agent         Evaluator
                    │              │
                    ↓              ↓
              More Investigation  PASS/FAIL
                    │              │
                    └──────┬───────┘
                           ↓
                     Final Report
                           │
                           ↓
                    Human Engineer
```

---

## 28. Core V1 Mental Model

The simplest way to understand the responsibility of each component is:

```text
Agent
→ Investigates and decides what to do next.

Tools
→ Give the agent capabilities.

analyze_log()
→ Understands raw logs.

search_security_knowledge()
→ Searches general security knowledge using semantic RAG.

get_incident_playbook()
→ Retrieves the complete investigation procedure for a known incident type.

search_cve()
→ Searches potentially relevant vulnerability information.

ChromaDB
→ Stores/indexes the searchable security knowledge.

Playbooks
→ Define the investigation procedure for each incident type.

Fine-Tuned LLM
→ Acts as the specialized security analyst.

Investigation State
→ Remembers everything discovered during the investigation.

Evaluator
→ Checks whether the investigation is complete, grounded, and meets the required criteria.

Final Report
→ Communicates the investigation results to the human security engineer.
```

The central design principle is:

> **The agent investigates, tools provide capabilities, RAG provides general security knowledge, playbooks provide investigation procedures, the fine-tuned model analyzes evidence, the evaluator checks the investigation, and the final report communicates the result.**
