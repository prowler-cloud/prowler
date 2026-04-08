from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.vercel.services.authentication.authentication_service import (
    VercelAuthToken,
)
from tests.providers.vercel.vercel_fixtures import set_mocked_vercel_provider


class Test_authentication_no_stale_tokens:
    def test_no_tokens(self):
        authentication_client = mock.MagicMock
        authentication_client.audit_config = {"stale_token_threshold_days": 90}
        authentication_client.tokens = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens import (
                authentication_no_stale_tokens,
            )

            check = authentication_no_stale_tokens()
            result = check.execute()
            assert len(result) == 0

    def test_token_active_recently(self):
        token_id = "tok_1"
        token_name = "Recent Token"
        active_at = datetime.now(timezone.utc) - timedelta(days=10)
        authentication_client = mock.MagicMock
        authentication_client.audit_config = {"stale_token_threshold_days": 90}
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                active_at=active_at,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens import (
                authentication_no_stale_tokens,
            )

            check = authentication_no_stale_tokens()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) was last active on {active_at.strftime('%Y-%m-%d %H:%M UTC')} (within the last 90 days)."
            )
            assert result[0].team_id is None

    def test_token_stale_90_days(self):
        token_id = "tok_2"
        token_name = "Stale Token"
        active_at = datetime.now(timezone.utc) - timedelta(days=120)
        days_inactive = (datetime.now(timezone.utc) - active_at).days
        authentication_client = mock.MagicMock
        authentication_client.audit_config = {"stale_token_threshold_days": 90}
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                active_at=active_at,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens import (
                authentication_no_stale_tokens,
            )

            check = authentication_no_stale_tokens()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) has not been used for {days_inactive} days (last active: {active_at.strftime('%Y-%m-%d %H:%M UTC')}). Threshold is 90 days."
            )
            assert result[0].team_id is None

    def test_token_no_activity(self):
        token_id = "tok_3"
        token_name = "Never Used Token"
        authentication_client = mock.MagicMock
        authentication_client.audit_config = {"stale_token_threshold_days": 90}
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                active_at=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_no_stale_tokens.authentication_no_stale_tokens import (
                authentication_no_stale_tokens,
            )

            check = authentication_no_stale_tokens()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) has no recorded activity and is considered stale."
            )
            assert result[0].team_id is None
