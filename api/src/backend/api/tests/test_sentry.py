import errno
import logging
from unittest.mock import MagicMock, patch

import pytest
from config.settings import sentry as sentry_settings
from config.settings.sentry import before_send, errno_fingerprint


def test_initialize_sentry_skips_without_dsn():
    with (
        patch.object(sentry_settings.env, "str", return_value=""),
        patch.object(sentry_settings.sentry_sdk, "init") as mock_init,
    ):
        sentry_settings.initialize_sentry()

    mock_init.assert_not_called()


def test_initialize_sentry_uses_configured_dsn():
    sentry_dsn = "https://fake-public-key@sentry.example.invalid/1"

    with (
        patch.object(sentry_settings.env, "str", return_value=sentry_dsn),
        patch.object(sentry_settings.sentry_sdk, "init") as mock_init,
    ):
        sentry_settings.initialize_sentry()

    assert mock_init.call_args.kwargs["dsn"] == sentry_dsn
    assert mock_init.call_args.kwargs["before_send"] is sentry_settings.before_send


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


def test_before_send_ignores_cartography_missing_temporary_database_log():
    log_record = _make_log_record(
        msg="Cartography job failed with %s for database %s",
        name="cartography.graph.job",
        args=(
            "Neo.ClientError.Database.DatabaseNotFound",
            "db-tmp-scan-12345678",
        ),
    )

    event = MagicMock()

    assert before_send(event, {"log_record": log_record}) is None


@pytest.mark.parametrize(
    ("logger_name", "message"),
    [
        (
            "cartography.graph.job.worker",
            "Neo.ClientError.Database.DatabaseNotFound for db-tmp-scan-12345678",
        ),
        (
            "cartography.graph.job",
            "DatabaseNotFound for db-tmp-scan-12345678",
        ),
        (
            "cartography.graph.job",
            "Neo.ClientError.Database.DatabaseNotFound for db-tenant-12345678",
        ),
    ],
)
def test_before_send_passes_through_similar_cartography_logs(logger_name, message):
    log_record = _make_log_record(msg=message, name=logger_name)
    event = MagicMock()

    assert before_send(event, {"log_record": log_record}) is event


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


@pytest.mark.parametrize(
    ("error_number", "message", "expected_suffix"),
    [
        (errno.ENOSPC, "No space left on device", "errno:ENOSPC"),
        (errno.ENOENT, "No such file or directory", "errno:ENOENT"),
        (errno.EACCES, "Permission denied", "errno:EACCES"),
    ],
)
def test_before_send_fingerprints_oserror_by_errno(
    error_number, message, expected_suffix
):
    """Filesystem failures raised from the same call site must not be merged."""
    exception = OSError(error_number, message)
    event = {}

    result = before_send(event, {"exc_info": (OSError, exception, None)})

    assert result is event
    assert event["fingerprint"] == ["{{ default }}", expected_suffix]


def test_before_send_fingerprints_differ_per_errno():
    """ENOSPC and ENOENT from the same call site produce different issues."""
    enospc_event = {}
    enoent_event = {}

    before_send(
        enospc_event,
        {"exc_info": (OSError, OSError(errno.ENOSPC, "No space left on device"), None)},
    )
    before_send(
        enoent_event,
        {
            "exc_info": (
                OSError,
                OSError(errno.ENOENT, "No such file or directory"),
                None,
            )
        },
    )

    assert enospc_event["fingerprint"] != enoent_event["fingerprint"]


def test_before_send_fingerprints_wrapped_oserror():
    """The errno is found even when the OSError is wrapped by another error."""
    try:
        try:
            raise OSError(errno.ENOSPC, "No space left on device")
        except OSError as os_error:
            raise RuntimeError("Error generating output directory") from os_error
    except RuntimeError as wrapper:
        event = {}
        before_send(event, {"exc_info": (RuntimeError, wrapper, None)})

    assert event["fingerprint"] == ["{{ default }}", "errno:ENOSPC"]


def test_before_send_does_not_fingerprint_non_oserror():
    """Non-filesystem exceptions keep Sentry's default grouping."""
    event = {}

    result = before_send(event, {"exc_info": (ValueError, ValueError("boom"), None)})

    assert result is event
    assert "fingerprint" not in event


def test_before_send_does_not_fingerprint_oserror_without_errno():
    """An OSError without errno has nothing to split the issue by."""
    event = {}

    before_send(event, {"exc_info": (OSError, OSError("no errno here"), None)})

    assert "fingerprint" not in event


def test_errno_fingerprint_uses_raw_number_for_unknown_errno():
    """Unmapped errno values still split the issue instead of being dropped."""
    assert errno_fingerprint(OSError(9999, "unknown")) == "errno:9999"


def test_errno_fingerprint_stops_on_self_referencing_chain():
    """A cyclic exception chain must not hang the fingerprint lookup."""
    first = ValueError("first")
    second = ValueError("second")
    first.__cause__ = second
    second.__cause__ = first

    assert errno_fingerprint(first) is None
