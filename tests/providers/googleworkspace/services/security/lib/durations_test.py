from datetime import datetime, timezone

import pytest

from prowler.providers.googleworkspace.services.security.lib.durations import (
    ONE_DAY_SECONDS,
    ONE_YEAR_SECONDS,
    TWO_WEEKS_SECONDS,
    format_duration,
    is_enforcement_active,
    parse_duration_seconds,
)


class TestParseDurationSeconds:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("0s", 0),
            ("86400s", ONE_DAY_SECONDS),
            ("1209600s", TWO_WEEKS_SECONDS),
            ("31536000s", ONE_YEAR_SECONDS),
            ("86400.9s", ONE_DAY_SECONDS),
            (" 86400s ", ONE_DAY_SECONDS),
        ],
    )
    def test_parses_protobuf_durations(self, value, expected):
        assert parse_duration_seconds(value) == expected

    @pytest.mark.parametrize(
        "value",
        [None, "", "86400", "28d", "P30D", "-3600s", "1e5s", "abc", 86400],
    )
    def test_returns_none_for_anything_it_cannot_read(self, value):
        """Callers must be able to tell a real length from an unreadable value"""
        assert parse_duration_seconds(value) is None


class TestFormatDuration:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("0s", "none"),
            ("86400s", "1 day(s)"),
            ("1209600s", "14 day(s)"),
            ("31536000s", "365 day(s)"),
            ("3600s", "3600 second(s)"),
            (None, "not configured"),
            ("28d", "not configured"),
        ],
    )
    def test_renders_for_finding_messages(self, value, expected):
        assert format_duration(value) == expected


class TestIsEnforcementActive:
    NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("2026-05-25T15:27:52.352Z", True),
            ("2026-08-25T11:59:59Z", True),
            ("2099-01-01T00:00:00Z", False),
            ("2026-12-31T23:59:59+00:00", False),
        ],
    )
    def test_compares_against_now(self, value, expected):
        assert is_enforcement_active(value, now=self.NOW) is expected

    def test_naive_timestamp_is_read_as_utc(self):
        assert is_enforcement_active("2026-01-01T00:00:00", now=self.NOW) is True

    @pytest.mark.parametrize("value", ["not-a-date", "", None])
    def test_unreadable_timestamp_does_not_fail_on_its_own(self, value):
        """A format Prowler cannot read must not become a failure by itself"""
        assert is_enforcement_active(value, now=self.NOW) is True
