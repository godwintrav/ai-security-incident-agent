from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "AI Security Incident Investigator"
    app_env: str = "development"
    database_url: str
    chroma_db_name: str
    embedding_model: str = "BAAI/bge-base-en-v1.5"
    autonoumous_investigation_model: str = "gpt-oss:20b"
    api_key: str

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()