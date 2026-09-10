from unittest.mock import MagicMock, patch

import pytest
from api.attack_paths.retryable_session import RetryableSession, RetryExhaustedError
from neo4j.exceptions import ServiceUnavailable


class TestRetryableSession:
    @patch("api.attack_paths.retryable_session.time.sleep")
    @patch("api.attack_paths.retryable_session.random.uniform", return_value=3.0)
    def test_custom_retry_uses_backoff_and_a_fresh_session(
        self, mock_uniform, mock_sleep
    ):
        retryable_error = RuntimeError("retryable")
        first_session = MagicMock()
        first_session.execute_write.side_effect = retryable_error
        second_session = MagicMock()
        second_session.execute_write.return_value = "success"
        session_factory = MagicMock(side_effect=[first_session, second_session])
        work = MagicMock()

        session = RetryableSession(
            session_factory=session_factory,
            max_retries=3,
            retry_if=lambda exc: exc is retryable_error,
            initial_retry_delay_seconds=2,
            retry_context="Neptune write",
        )

        assert session.execute_write(work) == "success"
        assert session_factory.call_count == 2
        first_session.close.assert_called_once_with()
        mock_uniform.assert_called_once_with(2.0, 4.0)
        mock_sleep.assert_called_once_with(3.0)

    def test_connection_errors_remain_retryable(self):
        first_session = MagicMock()
        first_session.run.side_effect = ServiceUnavailable("unavailable")
        second_session = MagicMock()
        second_session.run.return_value = "success"
        session_factory = MagicMock(side_effect=[first_session, second_session])

        session = RetryableSession(session_factory=session_factory, max_retries=1)

        assert session.run("RETURN 1") == "success"
        first_session.close.assert_called_once_with()

    def test_non_retryable_error_is_raised_without_refreshing_session(self):
        error = RuntimeError("do not retry")
        driver_session = MagicMock()
        driver_session.execute_write.side_effect = error
        session_factory = MagicMock(return_value=driver_session)
        session = RetryableSession(
            session_factory=session_factory,
            max_retries=3,
            retry_if=lambda _: False,
            initial_retry_delay_seconds=2,
            retry_context="Neptune write",
        )

        with pytest.raises(RuntimeError) as exc_info:
            session.execute_write(MagicMock())

        assert exc_info.value is error
        session_factory.assert_called_once_with()
        driver_session.close.assert_not_called()

    def test_retry_exhaustion_raises_the_last_error(self):
        error = RuntimeError("still retryable")
        driver_sessions = [MagicMock() for _ in range(3)]
        for driver_session in driver_sessions:
            driver_session.execute_write.side_effect = error
        session_factory = MagicMock(side_effect=driver_sessions)
        session = RetryableSession(
            session_factory=session_factory,
            max_retries=2,
            retry_if=lambda _: True,
        )

        with pytest.raises(RuntimeError) as exc_info:
            session.execute_write(MagicMock())

        assert exc_info.value is error
        assert session_factory.call_count == 3
        driver_sessions[0].close.assert_called_once_with()
        driver_sessions[1].close.assert_called_once_with()
        driver_sessions[2].close.assert_not_called()

    def test_retry_exhaustion_with_context_reports_attempts_and_elapsed_time(self):
        error = RuntimeError("still retryable")
        driver_sessions = [MagicMock() for _ in range(3)]
        for driver_session in driver_sessions:
            driver_session.execute_write.side_effect = error
        session = RetryableSession(
            session_factory=MagicMock(side_effect=driver_sessions),
            max_retries=2,
            retry_if=lambda _: True,
            retry_context="Neptune write",
        )

        with (
            patch(
                "api.attack_paths.retryable_session.time.monotonic",
                side_effect=[100.0, 127.1234],
            ),
            pytest.raises(RetryExhaustedError) as exc_info,
        ):
            session.execute_write(MagicMock())

        assert exc_info.value.method_name == "execute_write"
        assert exc_info.value.attempts == 3
        assert exc_info.value.elapsed_seconds == pytest.approx(27.1234)
        assert exc_info.value.last_error is error
        assert exc_info.value.__cause__ is error
        assert str(exc_info.value) == (
            "Neptune write execute_write failed after 3 attempts over 27.123s. "
            "Last error: still retryable"
        )

    def test_retry_exhaustion_with_zero_retries_reports_one_attempt(self):
        error = ServiceUnavailable("still unavailable")
        driver_session = MagicMock()
        driver_session.execute_write.side_effect = error
        session = RetryableSession(
            session_factory=MagicMock(return_value=driver_session),
            max_retries=0,
            retry_context="Neptune write",
        )

        with pytest.raises(RetryExhaustedError) as exc_info:
            session.execute_write(MagicMock())

        assert exc_info.value.attempts == 1

    @patch("api.attack_paths.retryable_session.time.sleep")
    @patch("api.attack_paths.retryable_session.random.uniform", return_value=3.0)
    def test_contextual_retry_warning_includes_original_error(
        self, _mock_uniform, _mock_sleep
    ):
        error = RuntimeError("retryable detail")
        first_session = MagicMock()
        first_session.execute_write.side_effect = error
        second_session = MagicMock()
        second_session.execute_write.return_value = "success"
        session = RetryableSession(
            session_factory=MagicMock(side_effect=[first_session, second_session]),
            max_retries=1,
            retry_if=lambda _: True,
            initial_retry_delay_seconds=2,
            retry_context="Neptune write",
        )

        with patch("api.attack_paths.retryable_session.logger.warning") as mock_warning:
            assert session.execute_write(MagicMock()) == "success"

        mock_warning.assert_called_once_with(
            "%s %s failed with %s: %s; retry %s/%s in %.3fs",
            "Neptune write",
            "execute_write",
            "RuntimeError",
            "retryable detail",
            1,
            1,
            3.0,
        )
