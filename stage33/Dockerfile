FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY research /app/research
COPY live /app/live

ENV PYTHONUNBUFFERED=1
ENV STAGE33_REPO_ROOT=/app
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["python", "-m", "research.stage33_external_verifier"]
