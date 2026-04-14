#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../src/backend"

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"
export DJANGO_BIND_ADDRESS="${DJANGO_BIND_ADDRESS:-0.0.0.0}"
export DJANGO_PORT="${PORT:-${DJANGO_PORT:-8080}}"
export DISABLE_NEO4J_INIT="${DISABLE_NEO4J_INIT:-1}"
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

if [[ "${RUN_DB_MIGRATIONS:-0}" == "1" ]]; then
	python manage.py migrate
fi

gunicorn -c config/guniconf.py config.wsgi:application