FROM python:3.12.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY migrations ./migrations

RUN python -m pip install --upgrade "pip==26.2.1" \
    && python -m pip install . \
    && groupadd --gid 10001 agentgate \
    && useradd --uid 10001 --gid agentgate --no-create-home --shell /usr/sbin/nologin agentgate \
    && mkdir -p /audit-checkpoint /evaluations/reports \
    && chown 10001:10001 /audit-checkpoint /evaluations/reports

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
