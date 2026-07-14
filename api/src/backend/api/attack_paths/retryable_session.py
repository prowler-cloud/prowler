import logging
import random
import time
from collections.abc import Callable
from typing import Any

import neo4j
import neo4j.exceptions

logger = logging.getLogger(__name__)


class RetryableSession:
    """Wrapper around ``neo4j.Session`` with a refreshable retry policy."""

    def __init__(
        self,
        session_factory: Callable[[], neo4j.Session],
        max_retries: int,
        retry_if: Callable[[Exception], bool] | None = None,
        initial_retry_delay_seconds: float = 0,
    ) -> None:
        self._session_factory = session_factory
        self._max_retries = max(0, max_retries)
        self._retry_if = retry_if
        self._initial_retry_delay_seconds = max(0.0, initial_retry_delay_seconds)
        self._session = self._session_factory()

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self) -> "RetryableSession":
        return self

    def __exit__(
        self, _: Any, __: Any, ___: Any
    ) -> None:  # Unused args:  exc_type, exc, exc_tb
        self.close()

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_with_retry("run", *args, **kwargs)

    def execute_write(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_with_retry("execute_write", *args, **kwargs)

    def execute_read(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_with_retry("execute_read", *args, **kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._session, item)

    def _call_with_retry(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        attempt = 0
        last_exc: Exception | None = None

        while attempt <= self._max_retries:
            try:
                method = getattr(self._session, method_name)
                return method(*args, **kwargs)

            except Exception as exc:
                if not self._should_retry(exc):
                    raise

                last_exc = exc
                attempt += 1

                if attempt > self._max_retries:
                    raise

                delay = self._retry_delay(attempt)
                logger.warning(
                    "Graph session %s failed with %s; retry %s/%s in %.3fs",
                    method_name,
                    type(exc).__name__,
                    attempt,
                    self._max_retries,
                    delay,
                )
                self._refresh_session()
                if delay:
                    time.sleep(delay)

        raise last_exc if last_exc else RuntimeError("Unexpected retry loop exit")

    def _should_retry(self, exc: Exception) -> bool:
        if isinstance(
            exc,
            (
                BrokenPipeError,
                ConnectionResetError,
                neo4j.exceptions.ServiceUnavailable,
            ),
        ):
            return True
        return self._retry_if(exc) if self._retry_if else False

    def _retry_delay(self, attempt: int) -> float:
        max_delay = self._initial_retry_delay_seconds * (2**attempt)
        return random.uniform(max_delay / 2, max_delay) if max_delay else 0

    def _refresh_session(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                # Best-effort close; failures just mean we open a new session below
                pass

        self._session = self._session_factory()
