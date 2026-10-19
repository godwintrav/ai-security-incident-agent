ANALYZE_LOG_FUNCTION = {
    "name": "analyze_log",
    "description": (
        "Analyze the raw security logs submitted for the current "
        "investigation and extract factual, incident-specific evidence. "
        "The application automatically retrieves the original logs "
        "from the investigation's internal state using its investigation ID; "
        "do not supply raw logs or an investigation ID. "
        "You must supply a clear, focused objective describing exactly "
        "what evidence to extract or which unanswered question to investigate. "
        "Use this tool for authentication events, source IP addresses, "
        "affected accounts, suspicious commands, timestamps, event sequences, "
        "or other activity actually observable in the logs. "
        "You may call this tool again with a different objective when "
        "the specialist identifies missing evidence that the existing "
        "logs could reasonably contain. "
        "Do not repeat an equivalent objective without new information. "
        "The tool returns a LogAnalysis containing an objective, extracted "
        "evidence, and observations. The application stores its result "
        "in investigation tool history; extracted evidence must be "
        "validated against the original logs before being accepted into "
        "the investigation evidence collection. "
        "Do not treat unsupported inferences as confirmed facts."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "objective": {
                "type": "string",
                "description": (
                    "A specific evidence-gathering objective for the "
                    "existing raw logs. For example: 'Identify successful "
                    "SSH logins, their source IP addresses, affected "
                    "accounts, and timestamps' or 'Identify commands "
                    "executed after the successful deploy login'. "
                    "Focus on what the logs can actually establish."
                ),
            },
        },
        "required": ["objective"],
        "additionalProperties": False,
    },
}


GET_INCIDENT_PLAYBOOK_FUNCTION = {
    "name": "get_incident_playbook",
    "description": (
        "Retrieve the security investigation and incident-response "
        "playbook for a suspected incident category. "
        "Use this tool when a plausible incident type has emerged "
        "from the description, logs, or extracted evidence, and "
        "procedural guidance would help the investigation. "
        "Supply the suspected incident type, such as "
        "'credential_compromise', 'brute_force', or "
        "'malware_execution', using a category supported by "
        "the playbook repository. "
        "The application retrieves the corresponding playbook from "
        "its internal playbook source, saves the tool result in "
        "investigation history, and makes the playbook available "
        "to the specialist through internal state. "
        "A playbook is reference guidance, not proof that the "
        "suspected incident occurred. "
        "Do not call repeatedly for the same incident type "
        "unless there is a meaningful reason."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "incident_type": {
                "type": "string",
                "description": (
                    "The suspected incident category used to retrieve "
                    "a relevant playbook. This is a provisional "
                    "investigation hypothesis, not a confirmed "
                    "classification."
                ),
            },
        },
        "required": ["incident_type"],
        "additionalProperties": False,
    },
}


SEARCH_CVE_FUNCTION = {
    "name": "search_cve",
    "description": (
        "Search for publicly documented software vulnerabilities "
        "associated with a specific product and version. "
        "Use only when the incident description or collected evidence "
        "identifies a relevant software product or component and "
        "there is a reasonable vulnerability-related investigation "
        "question. Supply both product and version. "
        "Do not invent a software version. If the version is unknown, "
        "do not call this tool until it can be established. "
        "The tool returns a CVESearchResult containing the searched "
        "product, version, total_results, and a list of vulnerabilities "
        "with CVE identifiers, descriptions, severity, scores, "
        "weaknesses, and references where available. "
        "The application saves the result in tool history and "
        "collects relevant successful CVE searches from internal "
        "state for the specialist's cve_results input. "
        "A matching CVE is reference information, not proof "
        "of exploitation. Avoid redundant searches."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "product": {
                "type": "string",
                "description": (
                    "The software product or component to investigate, "
                    "for example 'OpenSSH' or 'Apache HTTP Server'. "
                    "Use a product grounded in available information."
                ),
            },
            "version": {
                "type": "string",
                "description": (
                    "The known software version to search, "
                    "for example '9.3'. Never guess a version."
                ),
            },
        },
        "required": ["product", "version"],
        "additionalProperties": False,
    },
}


SEARCH_SECURITY_KNOWLEDGE_FUNCTION = {
    "name": "search_security_knowledge",
    "description": (
        "Search the internal security knowledge base for relevant "
        "security concepts, attack techniques, investigative "
        "guidance, and explanations of observed behaviors. "
        "The application searches its indexed security documents "
        "and returns a SecurityKnowledgeSearchResult. "
        "Supply a focused natural-language query based on the "
        "incident and available evidence. "
        "Use this tool when additional security context could help "
        "interpret observed activity, understand a suspected "
        "technique, or guide further investigation. "
        "The application stores the search result in tool history "
        "and makes relevant retrieved knowledge available to "
        "the specialist through internal state. "
        "Retrieved knowledge is contextual reference material, "
        "not incident-specific evidence. "
        "Do not repeat substantially equivalent queries "
        "without a meaningful reason."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "A focused security knowledge search query, "
                    "for example 'SSH password spraying versus "
                    "brute-force indicators' or 'Security significance "
                    "of reading /etc/shadow after SSH authentication'."
                ),
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}


ANALYZE_INCIDENT_WITH_SPECIALIST_FUNCTION = {
    "name": "analyze_incident_with_specialist",
    "description": (
        "Invoke the fine-tuned security incident specialist to "
        "analyze all currently accumulated, validated investigation "
        "evidence and relevant security reference context. "
        "This tool takes NO arguments. "
        "The application automatically builds IncidentAnalysisInput "
        "from internal investigation state, including the incident "
        "description, optional incident type, accumulated evidence, "
        "relevant security knowledge, playbook, and CVE search results. "
        "Do not supply an investigation ID, evidence, raw logs, "
        "or any other parameters. "
        "The specialist returns IncidentAnalysis containing "
        "incident classification, indicators of compromise, "
        "findings, missing_evidence, analysis_summary, severity, "
        "and confidence. "
        "The application saves the analysis and increments the "
        "specialist-analysis iteration count. "
        "Call this tool after collecting useful incident evidence "
        "and relevant context. "
        "If its missing_evidence identifies questions that can "
        "reasonably be addressed using the available investigation "
        "tools, investigate those gaps before calling it again. "
        "Do not invoke the specialist again when no meaningful "
        "new evidence or reference context has been obtained. "
        "You may invoke this tool AT MOST THREE TIMES for the "
        "entire investigation. "
        "The third specialist result is final, regardless of "
        "remaining missing evidence. "
        "Never invent evidence to satisfy missing_evidence."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
}


def get_tools() -> list[dict]:
    return [
        {
            "type": "function",
            "function": ANALYZE_LOG_FUNCTION,
        },
        {
            "type": "function",
            "function": GET_INCIDENT_PLAYBOOK_FUNCTION,
        },
        {
            "type": "function",
            "function": SEARCH_CVE_FUNCTION,
        },
        {
            "type": "function",
            "function": SEARCH_SECURITY_KNOWLEDGE_FUNCTION,
        },
        {
            "type": "function",
            "function": ANALYZE_INCIDENT_WITH_SPECIALIST_FUNCTION,
        },
    ]
