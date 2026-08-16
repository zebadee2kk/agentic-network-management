FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN useradd --create-home --uid 10001 anm

COPY pyproject.toml /app/pyproject.toml
COPY services/control_api /app/services/control_api
COPY migrations /app/migrations
COPY schemas /app/schemas
COPY alembic.ini /app/alembic.ini

RUN pip install --upgrade pip && pip install .

USER anm

CMD ["sh", "-c", "alembic upgrade head && uvicorn anm.main:app --host 0.0.0.0 --port 8000"]
