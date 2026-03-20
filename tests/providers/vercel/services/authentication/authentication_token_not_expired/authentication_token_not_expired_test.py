from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.vercel.services.authentication.authentication_service import (
    VercelAuthToken,
)
from tests.providers.vercel.vercel_fixtures import set_mocked_vercel_provider


class Test_authentication_token_not_expired:
    def test_no_tokens(self):
        authentication_client = mock.MagicMock
        authentication_client.tokens = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired import (
                authentication_token_not_expired,
            )

            check = authentication_token_not_expired()
            result = check.execute()
            assert len(result) == 0

    def test_token_not_expired(self):
        token_id = "tok_1"
        token_name = "My Token"
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        authentication_client = mock.MagicMock
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                expires_at=expires_at,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired import (
                authentication_token_not_expired,
            )

            check = authentication_token_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) is valid and expires on {expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
            )
            assert result[0].team_id is None

    def test_token_expired(self):
        token_id = "tok_2"
        token_name = "Old Token"
        expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        authentication_client = mock.MagicMock
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                expires_at=expires_at,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired import (
                authentication_token_not_expired,
            )

            check = authentication_token_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) has expired on {expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
            )
            assert result[0].team_id is None

    def test_token_no_expiration(self):
        token_id = "tok_3"
        token_name = "Permanent Token"
        authentication_client = mock.MagicMock
        authentication_client.tokens = {
            token_id: VercelAuthToken(
                id=token_id,
                name=token_name,
                expires_at=None,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired.authentication_client",
                new=authentication_client,
            ),
        ):
            from prowler.providers.vercel.services.authentication.authentication_token_not_expired.authentication_token_not_expired import (
                authentication_token_not_expired,
            )

            check = authentication_token_not_expired()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == token_id
            assert result[0].resource_name == token_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Token '{token_name}' ({token_id}) does not have an expiration date set and is currently valid."
            )
            assert result[0].team_id is None
