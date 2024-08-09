#!/bin/sh


apply_migrations() {
  echo "Applying database migrations..."
  poetry run python manage.py migrate --database admin
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
  echo "Starting the development worker..."
  poetry run python -m celery -A config.celery worker -l "${DJANGO_LOGGING_LEVEL:-info}"
}

case "$1" in
  dev)
    apply_migrations
    start_dev_server
    ;;
  prod)
    apply_migrations
    start_prod_server
    ;;
  worker)
    start_worker
    ;;
  *)
    echo "Usage: $0 {dev|prod|worker}"
    exit 1
    ;;
esac
