import logging
import multiprocessing
import os
import threading

from config.env import env

# Ensure the environment variable for Django settings is set
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.django.production")

# Import Django and set it up before accessing settings
import django  # noqa: E402

django.setup()
from api.compliance import warm_compliance_caches  # noqa: E402
from config.django.production import LOGGING as DJANGO_LOGGERS, DEBUG  # noqa: E402
from config.custom_logging import BackendLogger  # noqa: E402

BIND_ADDRESS = env("DJANGO_BIND_ADDRESS", default="127.0.0.1")
PORT = env("DJANGO_PORT", default=8080)

# Server settings
bind = f"{BIND_ADDRESS}:{PORT}"

workers = env.int("DJANGO_WORKERS", default=multiprocessing.cpu_count() * 2 + 1)
reload = DEBUG

# Native ASGI worker (gunicorn 24+). Required so SSE endpoints can keep the
# event loop alive while waiting for events.
worker_class = env("DJANGO_WORKER_CLASS", default="asgi")

# Lifespan protocol. Django's ASGIHandler (config.asgi:application) serves only
# HTTP scopes and raises "Django can only handle ASGI/HTTP connections, not
# lifespan." gunicorn's default ("auto") probes the app with a lifespan scope
# to detect support, which triggers that error. We use no lifespan startup or
# shutdown hooks, so disable the protocol entirely.
asgi_lifespan = env("DJANGO_ASGI_LIFESPAN", default="off")

# Event loop for the ASGI worker. "auto" uses uvloop when it is installed and
# falls back to the stdlib asyncio loop otherwise; uvloop gives the SSE event
# loop more headroom under many concurrent open streams.
asgi_loop = env("DJANGO_ASGI_LOOP", default="uvloop")

# Max concurrent connections per ASGI worker. Each open SSE stream holds one
# connection for its whole lifetime, so this caps simultaneous SSE clients per
# worker (gunicorn's default is 1000). The sync-only `threads` option has no
# effect on ASGI workers.
worker_connections = env.int("DJANGO_WORKER_CONNECTIONS", default=1000)

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
    """Warm compliance caches after each worker fork.

    Warm compliance caches in a background thread so the worker becomes ready
    immediately. A request for a not-yet-warmed provider lazily loads just that
    provider, which stays well under the worker timeout.
    """
    threading.Thread(
        target=_warm_compliance_caches_in_background,
        name="warm-compliance-caches",
        daemon=True,
    ).start()
