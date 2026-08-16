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
    schema_root: Path = Path("schemas")
    opa_timeout_seconds: float = Field(default=2.0, gt=0, le=10)
    dependency_timeout_seconds: float = Field(default=2.0, gt=0, le=10)

    # Autonomy Level 2 is the safe default: write proposals require human approval.
    # Phase 5 never executes a proposal regardless of this value.
    autonomy_level: int = Field(default=2, ge=0, le=4)

    # AI is optional and disabled by default. Monitoring and deterministic
    # incident workflows must not depend on any model provider.
    ai_enabled: bool = False
    model_relay_url: str = "http://model-relay:8090"
    model_timeout_seconds: float = Field(default=45.0, gt=0, le=180)
    ai_max_evidence_events: int = Field(default=50, ge=1, le=250)
    ai_max_context_chars: int = Field(default=40000, ge=2000, le=200000)
    ai_local_provider_hosts: str = "ollama,litellm"

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"

    @property
    def local_provider_hosts(self) -> set[str]:
        return {
            item.strip().lower()
            for item in self.ai_local_provider_hosts.split(",")
            if item.strip()
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
