#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../src/backend"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"
export DJANGO_BIND_ADDRESS="${DJANGO_BIND_ADDRESS:-0.0.0.0}"
export DJANGO_PORT="${PORT:-${DJANGO_PORT:-8080}}"

python manage.py migrate
gunicorn -c config/guniconf.py config.wsgi:application