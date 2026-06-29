import logging
import multiprocessing
import os
import threading

from config.env import env
from uvicorn_worker import UvicornWorker

# Ensure the environment variable for Django settings is set
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")

# Import Django and set it up before accessing settings
import django  # noqa: E402

django.setup()

from api.compliance import warm_compliance_caches  # noqa: E402
from config.custom_logging import BackendLogger  # noqa: E402
from config.django.production import DEBUG  # noqa: E402
from config.django.production import LOGGING as DJANGO_LOGGERS  # noqa: E402

BIND_ADDRESS = env("DJANGO_BIND_ADDRESS", default="127.0.0.1")
PORT = env("DJANGO_PORT", default=8080)


class ProwlerUvicornWorker(UvicornWorker):
    CONFIG_KWARGS = {
        # Keep-alive idle timeout. Must exceed the load balancer idle timeout.
        "timeout_keep_alive": env.int("GUNICORN_KEEPALIVE", default=75),
        "loop": "uvloop",
        "lifespan": "off",  # Django ASGIHandler doesn't handle lifespan scopes
    }


# Required so SSE endpoints can keep the event loop alive while waiting for events
worker_class = env(
    "DJANGO_WORKER_CLASS",
    default="config.guniconf.ProwlerUvicornWorker",
)

# Server settings
bind = f"{BIND_ADDRESS}:{PORT}"

workers = env.int("DJANGO_WORKERS", default=multiprocessing.cpu_count() * 2 + 1)
reload = DEBUG

# Preload the application before forking workers in production: the app is
# imported once in the master and workers fork from it. In development, disable
# preload so the server restarts on code changes.
preload_app = not DEBUG

# Worker timeout in seconds. Increased from the default 30s to handle requests
# that may take longer, such as complex API operations.
timeout = env.int("GUNICORN_TIMEOUT", default=120)

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


def _warm_compliance_caches_in_background():
    """Warm compliance caches off the request path and log the outcome."""
    failed = warm_compliance_caches()
    if failed:
        gunicorn_logger.warning("Compliance caches warmed (skipped: %s)", failed)
    else:
        gunicorn_logger.info("Compliance caches warmed")


def post_fork(_server, worker):
    """Re-initialize attack-paths drivers and warm compliance caches per worker.

    Neo4j / Neptune drivers spawn background IO threads that do not survive
    ``fork()``. When the gunicorn master runs with ``preload_app=True``, the
    child inherits driver objects whose pool references dead threads and
    hangs on the first ``pool.acquire`` call until the watchdog kills the
    worker. Re-initializing per worker guarantees each child owns its own
    live threads. See GUNICORN_WORKER_TIMEOUTS_ANALYSIS.md for detail.

    Compliance caches are then warmed in a background thread so the worker
    becomes ready immediately. A request for a not-yet-warmed provider lazily
    loads just that provider, which stays well under the worker timeout.
    """
    from api.attack_paths import database as graph_database

    try:
        graph_database.close_driver()
    except Exception:  # pragma: no cover - best-effort cleanup
        gunicorn_logger.debug(
            f"Failed to close inherited Neo4j driver in post_fork for worker pid={worker.pid}",
            exc_info=True,
        )
    graph_database.init_driver()
    gunicorn_logger.info(f"Attack-paths drivers initialized for worker {worker.pid}")

    threading.Thread(
        target=_warm_compliance_caches_in_background,
        name="warm-compliance-caches",
        daemon=True,
    ).start()
