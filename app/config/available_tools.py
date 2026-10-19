from app.schemas.evaluator_input_model import ToolCapability

AVAILABLE_TOOLS = [
    ToolCapability(
        tool_name=ToolName.ANALYZE_LOG,
        description="Analyze uploaded investigation logs and extract evidence.",
        available=True,
        required_arguments=["objective"],
        capabilities=[
            "Extract evidence from uploaded logs",
            "Identify suspicious activity in existing logs",
        ],
        limitations=[
            "Cannot retrieve logs that were not uploaded",
            "Cannot query live endpoints or external SIEM systems",
        ],
    ),
    ToolCapability(
        tool_name=ToolName.GET_INCIDENT_PLAYBOOK,
        description="Retrieve an incident investigation playbook.",
        available=True,
        required_arguments=["incident_type"],
        capabilities=[
            "Retrieve investigation steps and reference guidance",
        ],
        limitations=[
            "Does not produce incident evidence",
        ],
    ),
    ToolCapability(
        tool_name=ToolName.SEARCH_CVE,
        description="Search for known vulnerabilities affecting a product.",
        available=True,
        required_arguments=["product", "version"],
        capabilities=[
            "Retrieve vulnerability intelligence",
        ],
        limitations=[
            "Cannot confirm exploitation in the investigated environment",
            "Requires an identifiable product and version",
        ],
    ),
    ToolCapability(
        tool_name=ToolName.SEARCH_SECURITY_KNOWLEDGE,
        description="Search the security knowledge base.",
        available=True,
        required_arguments=["query"],
        capabilities=[
            "Retrieve relevant security knowledge and attack techniques",
        ],
        limitations=[
            "Does not produce incident evidence",
        ],
    ),
]