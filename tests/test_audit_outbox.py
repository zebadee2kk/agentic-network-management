from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from anm.auth import Principal
from anm.db import Base
from anm.models import AuditEvent, OutboxEvent
from anm.services.audit import AuditService


def test_audit_outbox_references_stable_event_id() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    principal = Principal(subject="tester", roles=("platform_admin",), provider="local")

    with Session(engine) as db:
        audit = AuditService.record(
            db,
            principal=principal,
            action="test.action",
            outcome="success",
            details={"safe": True},
        )
        db.commit()

        stored_audit = db.scalar(select(AuditEvent))
        outbox = db.scalar(select(OutboxEvent))
        assert stored_audit is not None
        assert outbox is not None
        assert stored_audit.id == audit.id
        assert outbox.payload["audit_event_id"] == str(audit.id)
        assert "secret" not in outbox.payload
