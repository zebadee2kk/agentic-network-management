from typing import Literal

from pydantic import BaseModel, Field


class ActionPolicyDecision(BaseModel):
    decision: Literal["deny", "require_approval", "allow"]
    reasons: list[str] = Field(default_factory=list)
    required_roles: list[str] = Field(default_factory=list)
    source: Literal["opa", "fail_closed"] = "opa"
    policy_version: str = Field(min_length=1, max_length=128)
