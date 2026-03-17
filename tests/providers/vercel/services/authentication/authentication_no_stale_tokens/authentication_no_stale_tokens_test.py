from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.vercel.services.authentication.authentication_service import (
    VercelAuthToken,
)
from tests.providers.vercel.vercel_fixtures import set_mocked_vercel_provider


class Test_authentication_no_stale_tokens:
    def test_no_tokens(self):
        authentication_client = mock.MagicMock
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
        authentication_client = mock.MagicMock
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                active_at=datetime.now(timezone.utc) - timedelta(days=10),
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
            assert "was last active on" in result[0].status_extended

    def test_token_stale_90_days(self):
        token_id = "tok_2"
        token_name = "Stale Token"
        authentication_client = mock.MagicMock
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                active_at=datetime.now(timezone.utc) - timedelta(days=120),
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
            assert "has not been used for" in result[0].status_extended

    def test_token_no_activity(self):
        token_id = "tok_3"
        token_name = "Never Used Token"
        authentication_client = mock.MagicMock
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
            assert "no recorded activity" in result[0].status_extended
