# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — builder
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Build-time system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency manifest and install into the system Python
COPY pyproject.toml ./
RUN uv pip install --system .

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        git \
    && apt-get install -y --no-install-recommends binwalk 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1000 argos \
 && useradd  --uid 1000 --gid argos --shell /bin/bash --create-home argos

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY argos/ ./argos/

# Ensure the non-root user owns the working directory
RUN chown -R argos:argos /app

USER argos

EXPOSE 8000

CMD ["uvicorn", "argos.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
