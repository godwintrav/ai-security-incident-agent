import os
from openai import OpenAI
from app.prompts.prompts import LOG_ANALYSIS_SYSTEM_PROMPT
from app.tools.models.analyze_log_model import LogAnalysis
from litellm import completion



class AnalyzeLog():
    """This class is responsible for analyzing the logs sent in by the user for investigation"""

    def __init__(self):
        self.APP_ENV = os.getenv(
                                "APP_ENV",
                                "development"
                            )
        if self.APP_ENV == 'production':
            self.API_KEY = os.getenv(
                                    "OPENAI_API_KEY",
                                    "development"
                                )
        else:
            self.API_KEY = "ollama"
        self.MODEL = "ollama/gpt-oss:20b"
        self.openai = OpenAI(base_url="http://localhost:11434/v1", api_key=self.API_KEY) if self.APP_ENV == 'development' else OpenAI(api_key=self.API_KEY)

    def analyze(self, raw_logs: str, objective: str) -> LogAnalysis:
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

        return LogAnalysis.model_validate_json(content)

