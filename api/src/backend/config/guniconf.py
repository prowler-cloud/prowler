import logging
import multiprocessing
import os

from config.env import env

# Ensure the environment variable for Django settings is set
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")

# Import Django and set it up before accessing settings
import django  # noqa: E402

django.setup()
from config.django.production import LOGGING as DJANGO_LOGGERS, DEBUG  # noqa: E402
from config.custom_logging import BackendLogger  # noqa: E402

BIND_ADDRESS = env("DJANGO_BIND_ADDRESS", default="127.0.0.1")
PORT = env("DJANGO_PORT", default=8080)

# Server settings
bind = f"{BIND_ADDRESS}:{PORT}"

workers = env.int("DJANGO_WORKERS", default=multiprocessing.cpu_count() * 2 + 1)
reload = DEBUG

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


def post_fork(_server, worker):
    """Re-initialize attack-paths drivers after each worker fork.

    Neo4j / Neptune drivers spawn background IO threads that do not survive
    ``fork()``. When the gunicorn master runs with ``preload_app=True``, the
    child inherits driver objects whose pool references dead threads and
    hangs on the first ``pool.acquire`` call until the watchdog kills the
    worker. Re-initializing per worker guarantees each child owns its own
    live threads. See GUNICORN_WORKER_TIMEOUTS_ANALYSIS.md for detail.
    """
    from api.attack_paths import database as graph_database

    try:
        graph_database.close_driver()
    except Exception:  # pragma: no cover - best-effort cleanup
        pass
    graph_database.init_driver()
    gunicorn_logger.info(f"Attack-paths drivers initialized for worker {worker.pid}")
