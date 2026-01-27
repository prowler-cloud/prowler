import traceback

from datetime import datetime, timezone


def stringify_exception(exception: Exception, context: str) -> str:
    timestamp = datetime.now(tz=timezone.utc)
    exception_traceback = traceback.TracebackException.from_exception(exception)
    traceback_string = "".join(exception_traceback.format())
    return f"{timestamp} - {context}\n{traceback_string}"
