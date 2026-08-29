from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from prowler.providers.snowflake.services.users.users_service import (
    USERS_QUERY,
    User,
    Users,
    _as_bool,
    _as_datetime,
)
from tests.providers.snowflake.snowflake_fixtures import set_mocked_snowflake_provider


class TestAsBool:
    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "t", "1", "yes", True])
    def test_truthy_values(self, value):
        assert _as_bool(value) is True

    @pytest.mark.parametrize(
        "value", ["false", "FALSE", "f", "0", "no", "", None, False]
    )
    def test_falsy_values(self, value):
        # The SQL API returns every column as a string, so a false boolean arrives as
        # the string "false" -- which is truthy in Python. Reading it naively would
        # report every user as MFA-enrolled and the check would silently never fire.
        assert _as_bool(value) is False


class TestAsDatetime:
    def test_parses_epoch_seconds(self):
        parsed = _as_datetime("1735689600.000")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_parses_iso_and_assumes_utc_when_naive(self):
        parsed = _as_datetime("2026-01-01T00:00:00")
        assert parsed == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_honours_an_explicit_offset(self):
        parsed = _as_datetime("2026-01-01T00:00:00+05:00")
        assert parsed.utcoffset() == timedelta(hours=5)

    @pytest.mark.parametrize("value", [None, "", "not-a-timestamp"])
    def test_unparseable_values_return_none(self, value):
        assert _as_datetime(value) is None


class TestUserModel:
    def test_native_mfa_counts_as_enrolment(self):
        assert User(name="A", has_mfa=True).mfa_enrolled is True

    def test_legacy_duo_still_counts_as_enrolment(self):
        # EXT_AUTHN_DUO is the only signal for an account enrolled through Duo. Keying
        # on HAS_MFA alone would report those users as unprotected.
        assert User(name="A", ext_authn_duo=True).mfa_enrolled is True

    def test_neither_column_means_not_enrolled(self):
        assert User(name="A").mfa_enrolled is False

    def test_a_future_bypass_window_is_an_open_bypass(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        assert (
            User(name="A", has_mfa=True, bypass_mfa_until=future).mfa_bypassed is True
        )

    def test_an_expired_bypass_window_is_closed(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        assert User(name="A", has_mfa=True, bypass_mfa_until=past).mfa_bypassed is False

    def test_no_bypass_column_means_not_bypassed(self):
        assert User(name="A", has_mfa=True).mfa_bypassed is False


class TestUsersService:
    def test_the_query_reads_both_mfa_columns_and_is_uncapped(self):
        # Both enrolment columns must be selected or the rule cannot consider them.
        assert "HAS_MFA" in USERS_QUERY
        assert "EXT_AUTHN_DUO" in USERS_QUERY
        assert "BYPASS_MFA_UNTIL" in USERS_QUERY
        # A row cap would silently under-report on a large account, and the oldest rows
        # -- where long-standing unprotected users live -- are the ones it would drop.
        assert "LIMIT" not in USERS_QUERY.upper()
        # Deleted users cannot sign in, so reporting them would be noise.
        assert "DELETED_ON IS NULL" in USERS_QUERY

    def test_users_are_parsed_from_account_usage(self):
        provider = set_mocked_snowflake_provider()
        provider.session.client.query.return_value = [
            {
                "NAME": "ALICE",
                "DISABLED": "false",
                "HAS_PASSWORD": "true",
                "HAS_RSA_PUBLIC_KEY": "false",
                "EXT_AUTHN_DUO": "false",
                "HAS_MFA": "true",
                "BYPASS_MFA_UNTIL": None,
                "DEFAULT_ROLE": "ANALYST",
                "TYPE": "PERSON",
                "LAST_SUCCESS_LOGIN": None,
                "CREATED_ON": None,
            }
        ]
        with mock.patch(
            "prowler.providers.snowflake.lib.service.service.SnowflakeProvider",
            new=mock.MagicMock(),
        ):
            service = Users(provider)

        assert len(service.users) == 1
        user = service.users[0]
        assert user.name == "ALICE"
        assert user.disabled is False
        assert user.has_password is True
        assert user.has_mfa is True
        assert user.default_role == "ANALYST"

    def test_a_failed_read_leaves_the_inventory_empty_without_raising(self):
        # One service failing must not abort the whole scan.
        provider = set_mocked_snowflake_provider()
        provider.session.client.query.side_effect = Exception(
            "ACCOUNT_USAGE unreadable"
        )
        with mock.patch(
            "prowler.providers.snowflake.lib.service.service.SnowflakeProvider",
            new=mock.MagicMock(),
        ):
            service = Users(provider)
        assert service.users == []
