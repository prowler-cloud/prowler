import logging
from unittest.mock import MagicMock

from config.settings.sentry import before_send


def test_before_send_ignores_log_with_ignored_exception():
    """Test that before_send ignores logs containing ignored exceptions."""
    log_record = MagicMock()
    log_record.msg = "Provider kubernetes is not connected"
    log_record.levelno = logging.ERROR  # 40

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
    log_record = MagicMock()
    log_record.msg = "Some other error message"
    log_record.levelno = logging.ERROR  # 40

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
    log_record = MagicMock()
    log_record.msg = "Provider kubernetes is not connected"
    log_record.levelno = logging.WARNING  # 30

    hint = {"log_record": log_record}

    event = MagicMock()

    result = before_send(event, hint)

    # Assert that the event was dropped (None returned)
    assert result is None


def test_before_send_ignores_neo4j_defunct_connection():
    """Test that before_send drops neo4j.io defunct connection logs.

    The Neo4j driver logs transient connection errors at ERROR level
    before RetryableSession retries them. These are noise.
    """
    log_record = MagicMock()
    log_record.name = "neo4j.io"
    log_record.msg = (
        "[#E5CC] _: <CONNECTION> error: Failed to read from defunct connection "
        "IPv4Address(('cloud-neo4j.prowler.com', 7687)) "
        "ConnectionResetError(104, 'Connection reset by peer')"
    )
    log_record.levelno = logging.ERROR

    hint = {"log_record": log_record}
    event = MagicMock()

    assert before_send(event, hint) is None


def test_before_send_passes_non_defunct_neo4j_log():
    """Test that before_send passes through neo4j.io logs that are not about defunct connections."""
    log_record = MagicMock()
    log_record.name = "neo4j.io"
    log_record.msg = "Some other neo4j transport error"
    log_record.levelno = logging.ERROR

    hint = {"log_record": log_record}
    event = MagicMock()

    assert before_send(event, hint) == event
