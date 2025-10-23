# =============================================================================
# Build stage - Install dependencies and build the application
# =============================================================================
FROM ghcr.io/astral-sh/uv:python3.13-alpine AS builder

WORKDIR /app

# Performance optimizations for uv:
# UV_COMPILE_BYTECODE=1: Pre-compile Python files to .pyc for faster startup
# UV_LINK_MODE=copy: Use copy instead of symlinks to avoid potential issues
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Install dependencies first for better Docker layer caching
# This allows dependency layer to be reused when only source code changes
COPY uv.lock pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# Copy all source code and install the project
# --frozen ensures reproducible builds by using exact versions from uv.lock
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

# =============================================================================
# Final stage - Minimal runtime environment
# =============================================================================
FROM python:3.13-alpine

LABEL maintainer="https://github.com/prowler-cloud"

# Create non-root user for security
# Using specific UID/GID for consistency across environments
RUN addgroup -g 1001 prowler && \
    adduser -D -u 1001 -G prowler prowler

WORKDIR /app
USER prowler

# Copy only the necessary files from builder stage to minimize image size:
# 1. Virtual environment with all dependencies and the installed package
COPY --from=builder --chown=prowler /app/.venv /app/.venv

# 2. Source code needed at runtime (for imports and module resolution)
COPY --from=builder --chown=prowler /app/prowler_mcp_server /app/prowler_mcp_server

# 3. Project metadata file (may be needed by some packages at runtime)
COPY --from=builder --chown=prowler /app/pyproject.toml /app/pyproject.toml

# 4. Entrypoint helper script for selecting runtime mode
COPY --from=builder --chown=prowler /app/entrypoint.sh /app/entrypoint.sh

# Add virtual environment to PATH so prowler-mcp command is available
ENV PATH="/app/.venv/bin:$PATH"

# Entrypoint wrapper defaults to CLI mode; override with `uvicorn` to run ASGI app
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["main"]
