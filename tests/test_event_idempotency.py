from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from anm.db import Base
from anm.models import EventProcessingReceipt, PlatformSetting
from anm.services.events import apply_test_event_once


def test_duplicate_message_mutates_domain_once() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        assert apply_test_event_once(db, message_id="msg-1", aggregate_key="asset-1") is True
        db.commit()

        assert apply_test_event_once(db, message_id="msg-1", aggregate_key="asset-1") is False
        db.commit()

        setting = db.get(PlatformSetting, "test-aggregate:asset-1")
        assert setting is not None
        assert setting.value["count"] == 1

        receipt_count = db.scalar(select(func.count()).select_from(EventProcessingReceipt))
        assert receipt_count == 1
