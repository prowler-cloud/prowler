#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../src/backend"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"

python -m celery -A config.celery beat \
  -l "${DJANGO_LOGGING_LEVEL:-info}" \
  --scheduler django_celery_beat.schedulers:DatabaseScheduler