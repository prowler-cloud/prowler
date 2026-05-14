import logging
from unittest.mock import MagicMock

from config.settings.sentry import before_send


def _make_log_record(msg, level=logging.ERROR, name="test", args=None):
    """Build a real LogRecord so getMessage() works like in production."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="",
        lineno=0,
        msg=msg,
        args=args,
        exc_info=None,
    )
    return record


def test_before_send_ignores_log_with_ignored_exception():
    """Test that before_send ignores logs containing ignored exceptions."""
    log_record = _make_log_record("Provider kubernetes is not connected")

    hint = {"log_record": log_record}
    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was dropped (None returned)
    assert result is None


def test_before_send_ignores_exception_with_ignored_exception():
    """Test that before_send ignores exceptions containing ignored exceptions."""
    exc_info = (Exception, Exception("Provider kubernetes is not connected"), None)

    hint = {"exc_info": exc_info}

    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was dropped (None returned)
    assert result is None


def test_before_send_passes_through_non_ignored_log():
    """Test that before_send passes through logs that don't contain ignored exceptions."""
    log_record = _make_log_record("Some other error message")

    hint = {"log_record": log_record}
    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was passed through
    assert result == event


def test_before_send_passes_through_non_ignored_exception():
    """Test that before_send passes through exceptions that don't contain ignored exceptions."""
    exc_info = (Exception, Exception("Some other error message"), None)

    hint = {"exc_info": exc_info}

    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was passed through
    assert result == event


def test_before_send_handles_warning_level():
    """Test that before_send handles warning level logs."""
    log_record = _make_log_record(
        "Provider kubernetes is not connected", level=logging.WARNING
    )

    hint = {"log_record": log_record}
    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was dropped (None returned)
    assert result is None


def test_before_send_ignores_neo4j_defunct_connection():
    """Test that before_send drops neo4j.io defunct connection logs.

    The Neo4j driver logs transient connection errors at ERROR level
    before RetryableSession retries them. These are noise.

    The driver uses %s formatting, so "defunct" is in the args, not
    in the template. This test mirrors the real LogRecord structure.
    """
    log_record = _make_log_record(
        msg="[#%04X]  _: <CONNECTION> error: %s: %r",
        name="neo4j.io",
        args=(
            0xE5CC,
            "Failed to read from defunct connection "
            "IPv4Address(('cloud-neo4j.prowler.com', 7687))",
            ConnectionResetError(104, "Connection reset by peer"),
        ),
    )

    hint = {"log_record": log_record}
    event = MagicMock()

    assert before_send(event, hint) is None


def test_before_send_passes_non_defunct_neo4j_log():
    """Test that before_send passes through neo4j.io logs that are not about defunct connections."""
    log_record = _make_log_record(
        msg="Some other neo4j transport error",
        name="neo4j.io",
    )

    hint = {"log_record": log_record}
    event = MagicMock()

    assert before_send(event, hint) == event
