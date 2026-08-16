import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from anm.config import get_settings
from anm.db import SessionLocal
from anm.routes import router
from anm.services.events import EventBus
from anm.services.policy import PolicyClient
from anm.services.secrets import OpenBaoClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.is_production and settings.auth_mode == "local":
        raise RuntimeError("ANM_AUTH_MODE=local is prohibited in production")

    app.state.policy_client = PolicyClient(settings)
    app.state.openbao_client = OpenBaoClient(settings)
    app.state.event_bus = EventBus(settings.nats_url, SessionLocal)

    # Keep the API live for diagnosis if NATS is unavailable; readiness remains failed.
    with suppress(Exception):
        await app.state.event_bus.start()

    yield

    if app.state.event_bus.connected:
        await app.state.event_bus.stop()


settings = get_settings()
app = FastAPI(
    title="Agentic Network Management",
    version="0.1.0",
    description="Policy-gated autonomous infrastructure and security operations control plane.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.ui_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = correlation_id
    return response


app.include_router(router)
