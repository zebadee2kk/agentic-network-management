FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/run/anm-executor

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10002 executor \
    && mkdir -p /run/anm-executor \
    && chown -R executor:executor /run/anm-executor

COPY pyproject.toml /app/pyproject.toml
COPY services/control_api /app/services/control_api
COPY schemas /app/schemas

RUN pip install --upgrade pip && pip install '.[executor]'

USER executor

CMD ["python", "-m", "anm.execution_worker"]
