# syntax=docker/dockerfile:1
FROM python:3.13-slim-bookworm AS base

# ---- build stage: compile wheels for deps that need a C toolchain ----
FROM base AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- runtime stage: slim image, non-root user ----
FROM base
WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home app

COPY --from=builder /root/.local /home/app/.local
COPY . .
RUN chown -R app:app /app

ENV PATH=/home/app/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER app
EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
