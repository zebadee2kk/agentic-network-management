import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from anm.db import Base
from anm.models import CredentialReference
from anm.schemas import CredentialReferenceCreate
from anm.services.secrets import OpenBaoClient


def test_api_schema_rejects_plaintext_secret_reference() -> None:
    with pytest.raises(ValidationError):
        CredentialReferenceCreate(name="firewall", secret_ref="SuperSecretPassword")


def test_database_rejects_non_openbao_reference() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(CredentialReference(name="bad", secret_ref="plaintext://secret"))
        with pytest.raises(IntegrityError):
            db.commit()


def test_openbao_reference_parser_requires_mount_and_path() -> None:
    assert OpenBaoClient.parse_reference("openbao://network/firewall/site-a") == (
        "network",
        "firewall/site-a",
    )
    with pytest.raises(ValueError):
        OpenBaoClient.parse_reference("openbao://network")
