from unittest import mock

import pytest

from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAuthenticationError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
)
from prowler.providers.supabase.lib.service.service import _rate_limit_delay
from prowler.providers.supabase.services.organizations import (
    organizations_service,
)
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_SLUG,
    USER_ID,
    set_mocked_supabase_provider,
)


class TestOrganizationsService:
    def test_fetches_members_without_storing_email(self):
        provider = set_mocked_supabase_provider()
        response = mock.MagicMock(status_code=200)
        response.json.return_value = [
            {
                "user_id": USER_ID,
                "user_name": "Test User",
                "email": "private@example.com",
                "role_name": "Owner",
                "mfa_enabled": False,
            }
        ]
        provider.session.http_session.get.return_value = response

        service = organizations_service.Organizations(provider)

        member = service.members[f"{ORGANIZATION_SLUG}:{USER_ID}"]
        assert member.id == USER_ID
        assert member.name == f"member {USER_ID}"
        assert member.organization_slug == ORGANIZATION_SLUG
        assert member.mfa_enabled is False
        assert "email" not in member.model_dump()
        assert "private@example.com" not in repr(member)

    @pytest.mark.parametrize(
        ("status_code", "exception"),
        [
            (401, SupabaseAuthenticationError),
            (403, SupabaseInsufficientPermissionsError),
            (429, SupabaseRateLimitError),
        ],
    )
    def test_api_errors_abort_collection_instead_of_producing_empty_results(
        self, status_code, exception
    ):
        provider = set_mocked_supabase_provider()
        provider.session.http_session.get.return_value = mock.MagicMock(
            status_code=status_code,
            headers={"X-RateLimit-Reset": "0"},
        )

        with pytest.raises(exception):
            organizations_service.Organizations(provider)

    def test_rate_limit_retries_using_reset_header(self):
        provider = set_mocked_supabase_provider()
        provider.audit_config = {"max_retries": 1}
        rate_limited = mock.MagicMock(
            status_code=429,
            headers={"X-RateLimit-Reset": "2"},
        )
        success = mock.MagicMock(status_code=200)
        success.json.return_value = []
        provider.session.http_session.get.side_effect = [rate_limited, success]

        with mock.patch(
            "prowler.providers.supabase.lib.service.service.time.sleep"
        ) as sleep:
            service = organizations_service.Organizations(provider)

        assert service.members == {}
        sleep.assert_called_once_with(2)


class TestRateLimitDelay:
    def test_relative_reset_seconds(self):
        assert _rate_limit_delay({"X-RateLimit-Reset": "2"}) == 2

    def test_retry_after_delta_seconds(self):
        assert _rate_limit_delay({"Retry-After": "3"}) == 3

    @mock.patch(
        "prowler.providers.supabase.lib.service.service.time.time",
        return_value=1_700_000_000,
    )
    def test_absolute_reset_timestamp(self, _):
        assert _rate_limit_delay({"X-RateLimit-Reset": "1700000005"}) == 5

    @mock.patch(
        "prowler.providers.supabase.lib.service.service.time.time",
        return_value=1_445_412_475,
    )
    def test_retry_after_http_date(self, _):
        headers = {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}

        assert _rate_limit_delay(headers) == 5

    @pytest.mark.parametrize(
        "malformed_value",
        ["not-a-timestamp", "inf", "nan"],
    )
    def test_malformed_headers_use_fallback(self, malformed_value):
        headers = {
            "X-RateLimit-Reset": malformed_value,
            "Retry-After": malformed_value,
        }

        assert _rate_limit_delay(headers) == 1

    def test_malformed_reset_uses_retry_after(self):
        headers = {
            "X-RateLimit-Reset": "not-a-timestamp",
            "Retry-After": "4",
        }

        assert _rate_limit_delay(headers) == 4

    @pytest.mark.parametrize(
        "headers",
        [
            {"X-RateLimit-Reset": "-5"},
            {"Retry-After": "-5"},
        ],
    )
    def test_negative_delay_is_clamped_to_zero(self, headers):
        assert _rate_limit_delay(headers) == 0

    @mock.patch(
        "prowler.providers.supabase.lib.service.service.time.time",
        return_value=1_700_000_000,
    )
    def test_past_absolute_reset_is_clamped_to_zero(self, _):
        assert _rate_limit_delay({"X-RateLimit-Reset": "1699999995"}) == 0

    def test_relative_delay_is_bounded(self):
        assert _rate_limit_delay({"X-RateLimit-Reset": "7200"}) == 3600
