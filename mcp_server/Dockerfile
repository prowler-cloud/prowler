# =============================================================================
# Build stage - Install dependencies and build the application
# =============================================================================
FROM ghcr.io/astral-sh/uv:0.11.21-python3.13-alpine3.23@sha256:f09cc61ffc001f202701fdeae14dbdd50f6ca4cfcf248f41fd3234a302c8534f AS builder

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
FROM python:3.14.6-alpine3.23@sha256:b165067c5afc37fa5608a3c05609cc3d51aafd808a30fbfd822ee594fef55ad4

LABEL maintainer="https://github.com/prowler-cloud"

# High CVEs fixed in Alpine 3.23 but not yet in the pinned base image:
#   sqlite-libs 3.53.4-r0  CVE-2026-11822, CVE-2026-11824  (image ships 3.51.2-r0)
#   libcrypto3/libssl3 3.5.8-r0  CVE-2026-14456            (image ships 3.5.7-r0)
# The base image pins python 3.13.14, which has not been rebuilt since those
# packages were published, so the upgrade is taken here rather than by moving
# the pin -- the newest published python:3.13-alpine3.23 carries the same
# vulnerable versions. libcrypto3 and libssl3 are both built from openssl and
# are flagged separately, so both are named.
# `>=` rather than `=`: Alpine keeps only the newest build of a package in a
# branch's index, so an exact pin breaks this build the day one of these is
# superseded. Drop an entry once the base image ships that version or later.
RUN apk add --no-cache --upgrade \
    "sqlite-libs>=3.53.4-r0" \
    "libcrypto3>=3.5.8-r0" \
    "libssl3>=3.5.8-r0"

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
