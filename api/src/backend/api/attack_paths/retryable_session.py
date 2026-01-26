import logging

from collections.abc import Callable
from typing import Any

import neo4j
import neo4j.exceptions

logger = logging.getLogger(__name__)


class RetryableSession:
    """
    Wrapper around `neo4j.Session` that retries `neo4j.exceptions.ServiceUnavailable` errors.
    """

    def __init__(
        self,
        session_factory: Callable[[], neo4j.Session],
        max_retries: int,
    ) -> None:
        self._session_factory = session_factory
        self._max_retries = max(0, max_retries)
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

    def write_transaction(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_with_retry("write_transaction", *args, **kwargs)

    def read_transaction(self, *args: Any, **kwargs: Any) -> Any:
        return self._call_with_retry("read_transaction", *args, **kwargs)

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

            except (
                BrokenPipeError,
                ConnectionResetError,
                neo4j.exceptions.ServiceUnavailable,
            ) as exc:  # pragma: no cover - depends on infra
                last_exc = exc
                attempt += 1

                if attempt > self._max_retries:
                    raise

                logger.warning(
                    f"Neo4j session {method_name} failed with {type(exc).__name__} ({attempt}/{self._max_retries} attempts). Retrying..."
                )
                self._refresh_session()

        raise last_exc if last_exc else RuntimeError("Unexpected retry loop exit")

    def _refresh_session(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                # Best-effort close; failures just mean we open a new session below
                pass

        self._session = self._session_factory()
