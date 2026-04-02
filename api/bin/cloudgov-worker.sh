#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../src/backend"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"
export NEO4J_HOST="${NEO4J_HOST:-}"
export NEO4J_PORT="${NEO4J_PORT:-}"
export NEO4J_USER="${NEO4J_USER:-}"
export NEO4J_PASSWORD="${NEO4J_PASSWORD:-}"

if [[ -z "${DATABASE_URL:-}" && -n "${VCAP_SERVICES:-}" ]]; then
  export DATABASE_URL="$(python - <<'PY'
import json
import os

services = json.loads(os.environ["VCAP_SERVICES"])
credentials = (services.get("aws-rds") or [{}])[0].get("credentials") or {}
print(credentials.get("uri", ""), end="")
PY
)"
fi

python -m celery -A config.celery worker \
  -l "${DJANGO_LOGGING_LEVEL:-info}" \
  --pool "${CELERY_WORKER_POOL:-solo}" \
  --concurrency "${CELERY_WORKER_CONCURRENCY:-1}" \
  -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
  -E --max-tasks-per-child 1 \
  --prefetch-multiplier "${CELERY_WORKER_PREFETCH_MULTIPLIER:-1}"