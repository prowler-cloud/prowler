#!/bin/sh

WORKER_NODENAME_FILE="${TMPDIR:-/tmp}/prowler-worker-nodename"

apply_migrations() {
  echo "Applying database migrations..."

  # Fix Inconsistent migration history after adding sites app
  uv run python manage.py check_and_fix_socialaccount_sites_migration --database admin

  uv run python manage.py migrate --database admin
}

apply_fixtures() {
  echo "Applying Django fixtures..."
  for fixture in api/fixtures/dev/*.json; do
    if [ -f "$fixture" ]; then
      echo "Loading $fixture"
      uv run python manage.py loaddata "$fixture" --database admin
    fi
  done
}

start_dev_server() {
  echo "Starting the development server (Gunicorn ASGI, debug + reload)..."
  # Same server/worker as prod (config.asgi via the native `asgi` worker), so
  # SSE streams run on the event loop exactly as they do in production. DEBUG is
  # on so guniconf's `reload = DEBUG` hot-reloads edited code (and flips
  # `preload_app` off so reload actually takes).
  export DJANGO_DEBUG="${DJANGO_DEBUG:-True}"
  export DJANGO_BIND_ADDRESS="${DJANGO_BIND_ADDRESS:-0.0.0.0}"
  exec uv run gunicorn -c config/guniconf.py config.asgi:application
}

start_prod_server() {
  echo "Starting the Gunicorn server..."
  exec uv run gunicorn -c config/guniconf.py config.asgi:application
}

resolve_worker_hostname() {
  TASK_ID=""

  if [ -n "$ECS_CONTAINER_METADATA_URI_V4" ]; then
    TASK_ID=$(wget -qO- --timeout=2 "${ECS_CONTAINER_METADATA_URI_V4}/task" | \
      python3 -c "import sys,json; print(json.load(sys.stdin)['TaskARN'].split('/')[-1])" 2>/dev/null)
  fi

  if [ -z "$TASK_ID" ]; then
    TASK_ID=$(python3 -c "import uuid; print(uuid.uuid4().hex)")
  fi

  echo "${TASK_ID}@$(hostname)"
}

start_worker() {
  echo "Starting the worker..."
  WORKER_NODENAME=$(resolve_worker_hostname)
  # Health checks run in a separate process and must use this exact identity.
  # Publish atomically so a probe cannot read a partially written name.
  NODENAME_TMP=$(mktemp "${WORKER_NODENAME_FILE}.XXXXXX") || exit 1
  if ! printf '%s\n' "$WORKER_NODENAME" > "$NODENAME_TMP" ||
     ! mv -fT "$NODENAME_TMP" "$WORKER_NODENAME_FILE"; then
    rm -f "$NODENAME_TMP"
    exit 1
  fi
  exec uv run python -m celery -A config.celery worker \
    -n "$WORKER_NODENAME" \
    -l "${DJANGO_LOGGING_LEVEL:-info}" \
    -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
    -E --max-tasks-per-child 1
}

check_worker_health() {
  if [ ! -s "$WORKER_NODENAME_FILE" ]; then
    echo "Worker identity is not available yet." >&2
    exit 1
  fi
  WORKER_NODENAME=$(cat "$WORKER_NODENAME_FILE")
  if [ -z "$WORKER_NODENAME" ]; then
    exit 1
  fi
  exec uv run python -m celery -A config.celery inspect ping \
    --destination "$WORKER_NODENAME" --timeout 5
}

start_worker_beat() {
  echo "Starting the worker-beat..."
  exec uv run python -m celery -A config.celery beat -l "${DJANGO_LOGGING_LEVEL:-info}" --scheduler django_celery_beat.schedulers:DatabaseScheduler
}

manage_db_partitions() {
  if [ "${DJANGO_MANAGE_DB_PARTITIONS}" = "True" ]; then
    echo "Managing DB partitions..."
    # For now we skip the deletion of partitions until we define the data retention policy
    # --yes auto approves the operation without the need of an interactive terminal
    uv run python manage.py pgpartition --using admin --skip-delete --yes
  fi
}

# Identify this process to Postgres (application_name=<component>:<alias>) so
# connections are attributable by component in pg_stat_activity. Web tiers
# report "api"; everything else uses the launch subcommand.
case "$1" in
  prod|dev) DJANGO_APP_COMPONENT="api" ;;
  *)        DJANGO_APP_COMPONENT="$1" ;;
esac
export DJANGO_APP_COMPONENT

case "$1" in
  dev)
    apply_migrations
    apply_fixtures
    manage_db_partitions
    start_dev_server
    ;;
  prod)
    apply_migrations
    manage_db_partitions
    start_prod_server
    ;;
  worker)
    start_worker
    ;;
  worker-healthcheck)
    check_worker_health
    ;;
  beat)
    start_worker_beat
    ;;
  *)
    echo "Usage: $0 {dev|prod|worker|worker-healthcheck|beat}"
    exit 1
    ;;
esac
