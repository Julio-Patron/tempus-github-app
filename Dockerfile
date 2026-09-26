# Multi-purpose lightweight production container for tempus-github-app
# Enforces zero-trust: no secrets baked into image, non-root user execution
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Install runtime security & performance dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root unprivileged operator user
RUN useradd -m -u 10001 tempus && \
    mkdir -p /app /data && \
    chown -R tempus:tempus /app /data

WORKDIR /app

# Install dependencies using pre-compiled wheels (no Rust toolchain required)
COPY --chown=tempus:tempus pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[server]"

# Copy application source code
COPY --chown=tempus:tempus src/ ./src/
RUN pip install --no-cache-dir --no-deps -e .

USER tempus

# Expose webhook port
EXPOSE 8000

# Default command runs the FastAPI webhook server
# Can be overridden with CLI: tempus-github-app-executor --permit /data/permit.json ...
CMD ["uvicorn", "tempus_github_app.server:create_webhook_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
