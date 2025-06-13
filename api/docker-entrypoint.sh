#!/bin/sh


apply_migrations() {
  echo "Applying database migrations..."

  # Fix Inconsistent migration history after adding sites app
  poetry run python manage.py check_and_fix_socialaccount_sites_migration --database admin

  poetry run python manage.py migrate --database admin
}

apply_fixtures() {
  echo "Applying Django fixtures..."
  for fixture in api/fixtures/dev/*.json; do
    if [ -f "$fixture" ]; then
      echo "Loading $fixture"
      poetry run python manage.py loaddata "$fixture" --database admin
    fi
  done
}

start_dev_server() {
  echo "Starting the development server..."
  poetry run python manage.py runserver 0.0.0.0:"${DJANGO_PORT:-8080}"
}

start_prod_server() {
  echo "Starting the Gunicorn server..."
  poetry run gunicorn -c config/guniconf.py config.wsgi:application
}

start_worker() {
  echo "Starting the worker..."
  poetry run python -m celery -A config.celery worker -l "${DJANGO_LOGGING_LEVEL:-info}" -Q celery,scans,scan-reports,deletion,backfill -E --max-tasks-per-child 1
}

start_worker_beat() {
  echo "Starting the worker-beat..."
  sleep 15
  poetry run python -m celery -A config.celery beat -l "${DJANGO_LOGGING_LEVEL:-info}" --scheduler django_celery_beat.schedulers:DatabaseScheduler
}

manage_db_partitions() {
  if [ "${DJANGO_MANAGE_DB_PARTITIONS}" = "True" ]; then
    echo "Managing DB partitions..."
    # For now we skip the deletion of partitions until we define the data retention policy
    # --yes auto approves the operation without the need of an interactive terminal
    poetry run python manage.py pgpartition --using admin --skip-delete --yes
  fi
}

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
  beat)
    start_worker_beat
    ;;
  *)
    echo "Usage: $0 {dev|prod|worker|beat}"
    exit 1
    ;;
esac
