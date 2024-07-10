import logging
import multiprocessing
import os

# Ensure the environment variable for Django settings is set
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.settings")

# Import Django and set it up before accessing settings
import django  # noqa: E402

django.setup()
from backend.settings import LOGGING as DJANGO_LOGGERS  # noqa: E402
from backend.custom_logging import BackendLogger  # noqa: E402

# Server settings
bind = ["0.0.0.0:8000"]
# Calculate the number of workers based on CPU count. Refactor when adding config from env vars
workers = multiprocessing.cpu_count() * 2 + 1
reload = True

# Logging
logconfig_dict = DJANGO_LOGGERS
gunicorn_logger = logging.getLogger(BackendLogger.GUNICORN)


# Hooks
def on_starting(_):
    gunicorn_logger.info(f"Starting gunicorn server with {workers} workers")
    if reload:
        gunicorn_logger.warning("Reload settings enabled (dev mode)")


def on_reload(_):
    gunicorn_logger.warning("Gunicorn server has reloaded")


def when_ready(_):
    gunicorn_logger.info("Gunicorn server is ready")
