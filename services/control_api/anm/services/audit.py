import uuid
from typing import Any

from sqlalchemy.orm import Session

from anm.auth import Principal
from anm.models import AuditEvent, OutboxEvent


class AuditService:
    @staticmethod
    def record(
        db: Session,
        *,
        principal: Principal,
        action: str,
        outcome: str,
        details: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor_type="user" if principal.provider != "service" else "service",
            actor_id=principal.subject,
            action=action,
            outcome=outcome,
            correlation_id=correlation_id,
            details=details or {},
        )
        db.add(event)

        message_id = str(uuid.uuid4())
        db.add(
            OutboxEvent(
                subject="audit.event",
                message_id=message_id,
                payload={
                    "message_id": message_id,
                    "audit_event_id": str(event.id),
                    "actor_type": event.actor_type,
                    "actor_id": event.actor_id,
                    "action": action,
                    "outcome": outcome,
                    "correlation_id": correlation_id,
                    "details": details or {},
                },
            )
        )
        return event
