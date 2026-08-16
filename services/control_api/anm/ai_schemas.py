import uuid
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ModelProviderCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    provider_type: Literal["openai_compatible"] = "openai_compatible"
    locality: Literal["external", "isolated_local"] = "external"
    base_url: str = Field(min_length=10, max_length=1024)
    model: str = Field(min_length=1, max_length=256)
    secret_ref: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("model base_url must use http:// or https:// with a host")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("model base_url must not contain credentials, query or fragment")
        if parsed.path.rstrip("/") != "/v1":
            raise ValueError("model base_url must end with /v1")
        return value.rstrip("/")

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_ref(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("openbao://"):
            raise ValueError("model provider secret references must use openbao://")
        return value

    @model_validator(mode="after")
    def external_provider_requires_secret(self) -> "ModelProviderCreate":
        if self.locality == "external" and not self.secret_ref:
            raise ValueError("external model providers require an OpenBao secret reference")
        return self


class ModelProviderResponse(ModelProviderCreate):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=2048)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=32)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=1, max_length=2048)
    rationale: str = Field(min_length=1, max_length=4096)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=32)


class InvestigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0.0"] = "1.0.0"
    role: Literal["soc_analyst", "network_analyst", "supervisor"]
    summary: str = Field(min_length=1, max_length=4096)
    confidence: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list, max_length=32)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=16)
    missing_evidence: list[str] = Field(default_factory=list, max_length=32)
    recommended_next_queries: list[str] = Field(default_factory=list, max_length=32)


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: uuid.UUID
    objective: str = Field(
        default="Investigate the incident, explain likely cause and identify missing evidence.",
        min_length=1,
        max_length=2048,
    )


class InvestigationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    provider_id: uuid.UUID
    status: str
    objective: str
    requested_by: str
    summary: str | None
    confidence: float | None
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float
    error_category: str | None
    error_detail: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class AgentStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_run_id: uuid.UUID
    role: str
    status: str
    tool_allowlist: list[str]
    evidence_digest: str | None
    output: dict[str, Any]
    error_detail: str | None
    started_at: datetime | None
    completed_at: datetime | None


class IncidentHypothesisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    investigation_run_id: uuid.UUID
    agent_role: str
    statement: str
    rationale: str
    confidence: float
    evidence_ids: list[str]
    status: str
    created_at: datetime


class AIStatusResponse(BaseModel):
    enabled: bool
    configured_providers: int
    architecture: Literal["isolated_worker_via_model_relay"] = "isolated_worker_via_model_relay"
