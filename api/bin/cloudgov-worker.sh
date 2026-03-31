#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../src/backend"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"

python -m celery -A config.celery worker \
  -l "${DJANGO_LOGGING_LEVEL:-info}" \
  -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
  -E --max-tasks-per-child 1