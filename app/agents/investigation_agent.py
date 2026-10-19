from typing import Any
import json

from pydantic import BaseModel

from app.agents.tool_definitions import get_tools
from app.config.available_tools import AVAILABLE_TOOLS
from app.config.settings import get_settings
import logging
from openai import AsyncOpenAI
from app.prompts.agent_prompts import INVESTIGATION_AGENT_SYSTEM_PROMPT, build_investigation_user_message
from app.schemas.analyze_incident_input_model import Evidence, Incident, IncidentAnalysisInput
from app.schemas.analyze_log_model import LogAnalysis
from app.schemas.analyzie_incident_output_model import IncidentAnalysis
from app.schemas.evaluator_input_model import AvailableDataSource, DataSourceAvailability, EvaluationInput, InvestigationAttempt, IterationBudget, PreviousEvaluation
from app.schemas.incident_playbook_model import IncidentPlaybook
from app.schemas.search_cve_model import CVESearchResult
from app.schemas.search_security_knowledge_model import SecurityKnowledgeSearchResult
from app.state.manager import InvestigationStateManager
from app.state.models import InvestigationStatus
from app.tools.analyze_incident import IncidentAnalyzerTool
from app.tools.analyze_log import AnalyzeLog
from app.tools.get_incident_playbook import IncidentPlaybookRetriever
from app.tools.search_cve import SearchCVE
from app.tools.search_security_knowledge import SearchSecurityKnowledge

class AutonomousInvestigationAgent():
    """This class is responsible is for being the orchestrator and deciding which tools to call until the investigation is complete"""

    def __init__(self, investigation_id: str, state_manager: InvestigationStateManager):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initialize Autonoumous Investigation agent")
        self.MODEL = get_settings().autonoumous_investigation_model
        print(get_settings().app_env)
        self.openai = AsyncOpenAI(base_url="http://localhost:11434/v1", api_key=get_settings().api_key) if get_settings().app_env == 'development' else AsyncOpenAI(api_key=get_settings().api_key)
        print(self.openai.base_url)
        self.investigation_id = investigation_id
        self.state_manager = state_manager
        self.analyze_log_tool = AnalyzeLog(state_manager)
        self.incident_playbook_retriever_tool = IncidentPlaybookRetriever()
        self.search_cve_tool = SearchCVE()
        self.search_security_knowledge_tool = SearchSecurityKnowledge()
        self.iteration = 0
        self.MAX_SPECIALIST_CALLS = 3
        self.incident_type = ""
        self.specialist_incident_analyzer = IncidentAnalyzerTool()
        self.latest_analysis: IncidentAnalysis

    async def get_logs(self, investigation_id: str) -> str:
        return await self.state_manager.get_investigation_logs(
            investigation_id
        )

    async def save_tool_result(
            self,
            tool_name: str,
            arguments: dict,
            result: dict | None,
            status: str,
            outcome: str,
            evidence_ids: list[str] | None = None,
            error: str | None = None,
    ) -> None:
        await self.state_manager.add_tool_result(
            investigation_id=self.investigation_id,
            tool_name=tool_name,
            result=result,
            iteration=self.iteration,
            arguments=arguments,
            status=status,
            outcome=outcome,
            evidence_ids=evidence_ids,
            error=error
        )

    async def analyze_log(self, objective: str) -> LogAnalysis:
        self.logger.info(f"Autonoumous Investigation agent is calling analyze log tool for investigation with id {self.investigation_id} and objective: {objective}")
        logs = await self.get_logs(self.investigation_id)
        try:
            result = await self.analyze_log_tool.analyze(logs, objective, self.investigation_id)

        except Exception as exc:
            self.logger.exception(
                "Analyze Log tool failed for investigation %s",
                self.investigation_id,
            )

            await self.state_manager.update_status(
                self.investigation_id,
                InvestigationStatus.FAILED,
            )

            raise

        await self.save_tool_result(
            tool_name="analyze_log",
            arguments={"objective": objective},
            result=result.model_dump(mode="json"),
            status="completed",
            outcome=(
                "evidence_found"
                if result.evidence
                else "no_matching_evidence"
            ),
            evidence_ids=[
                evidence.id
                for evidence in result.evidence
            ],
        )
        return result

    async def get_incident_playbook(self, incident_type: str) -> IncidentPlaybook:
        self.logger.info(f"Autonoumous Investigation agent is calling get incident playbook tool for investigation with id {self.investigation_id} and incident type: {incident_type}")
        try:
            playbook = self.incident_playbook_retriever_tool.get_incident_playbook(incident_type=incident_type)

        except Exception as exc:
            self.logger.exception(
                "Get incident Playbook tool failed for investigation %s",
                self.investigation_id,
            )

            await self.state_manager.update_status(
                self.investigation_id,
                InvestigationStatus.FAILED,
            )

            raise
        self.incident_type = playbook.incident_type
        await self.state_manager.update_incident_type(self.investigation_id, playbook.incident_type)
        await self.save_tool_result(
                tool_name="get_incident_playbook",
                arguments={"incident_type": incident_type},
                result=playbook.model_dump(mode="json"),
                status="completed",
                outcome=(
                    "context_found"
                    if playbook
                    else "no_matching_context"
                ),
                evidence_ids=[],
            )
        return playbook

    async def search_cve(self, product: str, version: str) -> CVESearchResult:
        self.logger.info(f"Autonoumous Investigation agent is calling search cve tool for investigation with id {self.investigation_id} and product: {product} and version: {version}")
        try:
            result = self.search_cve_tool.search_cve(product=product, version=version)

        except Exception as exc:
            self.logger.exception(
                "Search CVE tool failed for investigation %s",
                self.investigation_id,
            )

            await self.state_manager.update_status(
                self.investigation_id,
                InvestigationStatus.FAILED,
            )

            raise
        await self.save_tool_result(
            tool_name="search_cve",
            arguments={"product": product, "version": version},
            result=result.model_dump(mode="json"),
            status="completed",
            outcome=(
                "context_found"
                if result
                else "no_matching_context"
            ),
            evidence_ids=[],
        )
        return result

    async def search_security_knowledge(self, query: str) -> SecurityKnowledgeSearchResult:
        self.logger.info(f"Autonoumous Investigation agent is calling search security knowledge tool for investigation with id {self.investigation_id} and query: {query}")

        try:
            result = self.search_security_knowledge_tool.search(query=query)

        except Exception as exc:
            self.logger.exception(
                "Search Security Knowledge tool failed for investigation %s",
                self.investigation_id,
            )

            await self.state_manager.update_status(
                self.investigation_id,
                InvestigationStatus.FAILED,
            )

            raise
        json_result = result.model_dump(mode="json")
        await self.save_tool_result(result=json_result, tool_name="search_security_knowledge")
        await self.save_tool_result(
            tool_name="search_security_knowledge",
            arguments={"query": query},
            result=result.model_dump(mode="json"),
            status="completed",
            outcome=(
                "context_found"
                if result
                else "no_matching_context"
            ),
            evidence_ids=[],
        )
        return result

    async def analyze_incident_with_specialist(self) -> IncidentAnalysis:
        self.logger.info(f"Autonoumous Investigation agent is calling specialist incident analyzer tool for investigation with id {self.investigation_id}")
        await self.state_manager.update_status(self.investigation_id, InvestigationStatus.ANALYZING)
        incident_analysis_input = await self.build_specialist_input()
        
        try:
            result = await self.specialist_incident_analyzer.analyze_incident(incident=incident_analysis_input)

        except Exception as exc:
            self.logger.exception(
                "Specialist analysis failed for investigation %s",
                self.investigation_id,
            )

            await self.state_manager.update_status(
                self.investigation_id,
                InvestigationStatus.FAILED,
            )

            raise
        json_result = result.model_dump(mode="json")
        await self.state_manager.add_analysis(self.investigation_id, json_result)
        await self.state_manager.update_iteration(self.investigation_id, self.iteration + 1)
        await self.state_manager.update_incident_type(self.investigation_id, result.incident_type)
        self.latest_analysis = result
        await self.state_manager.update_status(self.investigation_id, InvestigationStatus.INVESTIGATING)
        return result

    async def build_specialist_input(
        self,
    ) -> IncidentAnalysisInput:

        state = await self.state_manager.get_investigation(self.investigation_id)

        return IncidentAnalysisInput(
            incident=Incident(
                description=state.description,
                incident_type=state.incident_type,
            ),
            evidence=[
                Evidence.model_validate(item)
                for item in state.evidence
            ],
            security_knowledge=self.__collect_tool_result_from_state(
                tool_name="search_security_knowledge",
                tool_results=state.tool_results,
            ),
            playbook=self.__collect_tool_result_from_state(
                tool_name="get_incident_playbook",
                tool_results=state.tool_results,
            ),
            cve_results=self.__collect_tool_result_from_state(
                tool_name="search_cve",
                tool_results=state.tool_results,
            ),
        )

    async def build_evaluation_input(self) -> EvaluationInput:
        state = self.state_manager.get_investigation(
            self.investigation_id
        )

        latest_analysis = state.analyses[-1]

        playbook = None

        for tool_result in reversed(state.tool_results):
            if tool_result["tool_name"] == "get_incident_playbook":
                if tool_result.get("status") == "completed":
                    playbook = tool_result.get("result")
                    break

        tool_history = [
            InvestigationAttempt(
                tool_name=result["tool_name"],
                arguments=result.get("arguments", {}),
                status=result.get("status", "completed"),
                outcome=result.get("outcome", "not_applicable"),
                evidence_ids=result.get("evidence_ids", []),
                result_summary=result.get("result"),
                error=result.get("error"),
            )
            for result in state.tool_results
        ]

        available_data_sources = [
            AvailableDataSource(
                name="uploaded_investigation_logs",
                availability=(
                    DataSourceAvailability.AVAILABLE
                    if state.logs
                    else DataSourceAvailability.UNAVAILABLE
                ),
                description=(
                    "Raw logs submitted with the investigation. "
                    "The agent can analyze these logs using analyze_log."
                ),
                log_types=[],
                limitations=[
                    "Only the submitted logs are accessible",
                    "No live endpoint, SIEM, or backup-system access",
                ],
            )
        ]

        previous_evaluations = [
            PreviousEvaluation(
                decision=evaluation["decision"],
                reasoning_summary=evaluation["reasoning_summary"],
                requested_tasks=[
                    task["investigation_question"]
                    for task in evaluation.get(
                        "investigation_tasks", []
                    )
                ],
                unresolved_questions=[
                    gap["question"]
                    for gap in evaluation.get(
                        "unresolved_gaps", []
                    )
                ],
            )
            for evaluation in getattr(state, "evaluations", [])
        ]

        max_specialist_calls = 3
        specialist_calls_used = len(state.analyses)

        return EvaluationInput(
            investigation_id=str(state.id),
            description=state.description,
            incident_type=latest_analysis["incident_type"],
            evidence=[
                e.model_dump(mode="json")
                if hasattr(e, "model_dump")
                else e
                for e in state.evidence
            ],
            latest_analysis=latest_analysis,
            playbook=playbook,
            tool_history=tool_history,
            available_tools=AVAILABLE_TOOLS,
            available_data_sources=available_data_sources,
            previous_evaluations=previous_evaluations,
            iteration_budget=IterationBudget(
                specialist_calls_used=specialist_calls_used,
                specialist_calls_remaining=max(
                    0,
                    max_specialist_calls - specialist_calls_used,
                ),
                max_new_tasks=3,
            ),
        )

    def __collect_tool_result_from_state(self, tool_name: str, tool_results: dict[str, Any]) -> dict[str, Any] | list[str] | list[dict[str, Any]]:
        if tool_name == "search_security_knowledge":
            return self.search_security_knowledge_tool.collect_tool_result_from_state(tool_results=tool_results, iteration=self.iteration)

        if tool_name == "search_cve":
            return self.search_cve_tool.collect_tool_result_from_state(tool_results=tool_results)

        if tool_name == "get_incident_playbook":
            return self.incident_playbook_retriever_tool.collect_tool_result_from_state(tool_results=tool_results, iteration=self.iteration)

    async def handle_tool_call(self, message):
        """
        Actually call the tools associated with this message
        """
        mapping = {
            "analyze_incident_with_specialist": self.analyze_incident_with_specialist,
            "search_security_knowledge": self.search_security_knowledge,
            "search_cve": self.search_cve,
            "get_incident_playbook": self.get_incident_playbook,
            "analyze_log": self.analyze_log,
        }
        results = []
        for tool_call in message.tool_calls:
            tool_name = tool_call.function.name
            arguments = json.loads(tool_call.function.arguments)
            tool = mapping.get(tool_name)
            result = await tool(**arguments) if tool else ""
            if isinstance(result, BaseModel):
                content = result.model_dump_json()
            elif isinstance(result, str):
                content = result
            else:
                content = json.dumps(result)

            results.append({
                "role": "tool",
                "content": content,
                "tool_call_id": tool_call.id,
            })
        return results

    async def run_investigation(self) -> None:
        self.logger.info("Autonomous Investigation Agent is kicking off a run")
        await self.state_manager.update_status(self.investigation_id, InvestigationStatus.INVESTIGATING)
        state = await self.state_manager.get_investigation(self.investigation_id)
        messages = [
            {
                "role": "system",
                "content": INVESTIGATION_AGENT_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": build_investigation_user_message(
                    investigation_id=str(state.id),
                    description=state.description,
                    specialist_calls=state.iteration,
                    tool_results=state.tool_results,
                    analyses=state.analyses,
                    evidence_count=len(state.evidence),
                    logs_available=bool(state.logs.strip()),
                ),
            },
        ]
        while self.iteration < self.MAX_SPECIALIST_CALLS:
            response = await self.openai.chat.completions.create(
                model=self.MODEL, messages=messages, tools=get_tools(), tool_choice="auto", parallel_tool_calls=False
            )
            if response.choices[0].finish_reason == "tool_calls":
                message = response.choices[0].message
                results = await self.handle_tool_call(message)
                messages.append(message)
                messages.extend(results)
            else:
                break
        await self.state_manager.update_status(self.investigation_id, InvestigationStatus.COMPLETED)
        reply = response.choices[0].message.content
        self.logger.info(f"Autonomous Planning Agent completed with: {reply}")
        return self.latest_analysis