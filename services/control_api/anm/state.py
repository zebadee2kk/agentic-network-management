from fastapi import Request

from anm.services.events import EventBus
from anm.services.policy import PolicyClient
from anm.services.secrets import OpenBaoClient


def get_event_bus(request: Request) -> EventBus:
    return request.app.state.event_bus


def get_policy_client(request: Request) -> PolicyClient:
    return request.app.state.policy_client


def get_openbao_client(request: Request) -> OpenBaoClient:
    return request.app.state.openbao_client
