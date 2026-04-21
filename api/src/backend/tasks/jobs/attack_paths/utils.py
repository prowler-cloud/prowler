import asyncio
import traceback

from datetime import datetime, timezone

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def stringify_exception(exception: Exception, context: str) -> str:
    """Format an exception with timestamp and traceback for logging."""
    timestamp = datetime.now(tz=timezone.utc)
    exception_traceback = traceback.TracebackException.from_exception(exception)
    traceback_string = "".join(exception_traceback.format())
    return f"{timestamp} - {context}\n{traceback_string}"


def call_within_event_loop(fn, *args, **kwargs):
    """
    Execute a function within a new event loop.

    Cartography needs a running event loop, so assuming there is none
    (Celery task or even regular DRF endpoint), this creates a new one
    and sets it as the current event loop for this thread.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return fn(*args, **kwargs)

    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())

        except Exception as e:
            logger.warning(f"Failed to shutdown async generators cleanly: {e}")

        loop.close()
        asyncio.set_event_loop(None)
