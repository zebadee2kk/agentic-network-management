from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ANM_",
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    env: str = "development"
    log_level: str = "INFO"
    auth_mode: str = "local"
    local_principal: str = "local-admin"
    database_url: str = "postgresql+psycopg://anm:anm@postgres:5432/anm"
    nats_url: str = "nats://nats:4222"
    opa_url: str = "http://opa:8181"
    openbao_url: str = "http://openbao:8200"
    openbao_token_file: Path = Path("/run/secrets/openbao_token")
    ui_origin: str = "http://localhost:8080"
    opa_timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    dependency_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
