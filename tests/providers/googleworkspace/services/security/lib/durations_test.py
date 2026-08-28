from datetime import datetime, timezone

import pytest

from prowler.providers.googleworkspace.services.security.lib.durations import (
    ONE_DAY_SECONDS,
    ONE_YEAR_SECONDS,
    TWO_WEEKS_SECONDS,
    enforcement_issue,
    format_duration,
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
            ("3600s", "1 hour(s)"),
            ("129600s", "36 hour(s)"),
            ("5400s", "5400 second(s)"),
            (None, "not configured"),
            ("28d", "not configured"),
        ],
    )
    def test_renders_for_finding_messages(self, value, expected):
        assert format_duration(value) == expected


class TestEnforcementIssue:
    NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)

    @pytest.mark.parametrize(
        "value", ["2026-05-25T15:27:52.352Z", "2026-08-25T11:59:59Z"]
    )
    def test_no_issue_once_enforcement_has_started(self, value):
        assert enforcement_issue(value, now=self.NOW) is None

    def test_naive_timestamp_is_read_as_utc(self):
        assert enforcement_issue("2026-01-01T00:00:00", now=self.NOW) is None

    @pytest.mark.parametrize("value", [None, ""])
    def test_missing_value_defaults_to_off(self, value):
        assert (
            enforcement_issue(value, now=self.NOW)
            == "enforcement is not configured and defaults to OFF"
        )

    @pytest.mark.parametrize(
        "value", ["1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000000Z"]
    )
    def test_zero_value_timestamp_is_off(self, value):
        """The API reports OFF as the protobuf zero-value Timestamp"""
        assert enforcement_issue(value, now=self.NOW) == "enforcement is set to OFF"

    @pytest.mark.parametrize(
        "value", ["2099-01-01T00:00:00Z", "2026-12-31T23:59:59+00:00"]
    )
    def test_future_start_date_means_nobody_is_enforced_yet(self, value):
        assert (
            enforcement_issue(value, now=self.NOW)
            == f"enforcement does not start until {value}"
        )

    def test_unreadable_timestamp_is_reported_instead_of_assumed_active(self):
        assert (
            enforcement_issue("not-a-date", now=self.NOW)
            == "the enforcement start date 'not-a-date' could not be read"
        )
