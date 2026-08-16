from dataclasses import dataclass
from typing import Protocol

from fastapi import Depends

from anm.config import Settings, get_settings


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: tuple[str, ...]
    provider: str


class AuthProvider(Protocol):
    def authenticate(self) -> Principal: ...


class LocalAuthProvider:
    """Development/community bootstrap provider.

    Production must use an external identity provider. The abstraction exists now so
    route authorization does not depend on how identity is obtained.
    """

    def __init__(self, settings: Settings) -> None:
        if settings.is_production:
            raise RuntimeError("local authentication is prohibited in production")
        self._principal = Principal(
            subject=settings.local_principal,
            roles=("platform_admin", "platform_approver"),
            provider="local",
        )

    def authenticate(self) -> Principal:
        return self._principal


def get_principal(settings: Settings = Depends(get_settings)) -> Principal:
    if settings.auth_mode != "local":
        raise RuntimeError(f"unsupported auth mode in Phase 1: {settings.auth_mode}")
    return LocalAuthProvider(settings).authenticate()
