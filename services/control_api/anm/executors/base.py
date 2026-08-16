from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ExecutionContext:
    execution_id: str
    capability: str
    target_asset_id: str
    endpoint: str
    parameters: dict[str, Any]
    binding_config: dict[str, Any]
    implementation: str
    secret: dict[str, Any] | None = None


@dataclass(frozen=True)
class ExecutionOutcome:
    outcome: str
    result: dict[str, Any] = field(default_factory=dict)
    pre_state: dict[str, Any] = field(default_factory=dict)
    category: str | None = None


class DeterministicExecutor(Protocol):
    async def execute(self, context: ExecutionContext) -> ExecutionOutcome: ...
