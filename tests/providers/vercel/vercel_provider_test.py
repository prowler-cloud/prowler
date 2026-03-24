import os
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.common.models import Connection
from prowler.providers.vercel.exceptions.exceptions import (
    VercelAuthenticationError,
    VercelCredentialsError,
)
from prowler.providers.vercel.models import VercelIdentityInfo, VercelSession
from prowler.providers.vercel.vercel_provider import VercelProvider
from tests.providers.vercel.vercel_fixtures import (
    API_TOKEN,
    TEAM_ID,
    TEAM_NAME,
    TEAM_SLUG,
    USER_EMAIL,
    USER_ID,
    USERNAME,
)


class TestVercelProviderSetupSession:
    def test_setup_session_with_env_var(self):
        with mock.patch.dict(os.environ, {"VERCEL_TOKEN": API_TOKEN}, clear=False):
            session = VercelProvider.setup_session()

        assert isinstance(session, VercelSession)
        assert session.token == API_TOKEN
        assert session.http_session is not None

    def test_setup_session_with_api_token_param(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = VercelProvider.setup_session(api_token=API_TOKEN)

        assert isinstance(session, VercelSession)
        assert session.token == API_TOKEN
        assert session.http_session is not None

    def test_setup_session_with_team_id_param(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = VercelProvider.setup_session(api_token=API_TOKEN, team_id=TEAM_ID)

        assert session.token == API_TOKEN
        assert session.team_id == TEAM_ID

    def test_setup_session_no_credentials_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VERCEL_TOKEN", None)
            with pytest.raises(VercelCredentialsError):
                VercelProvider.setup_session()

    def test_setup_session_team_from_env(self):
        with mock.patch.dict(
            os.environ, {"VERCEL_TOKEN": API_TOKEN, "VERCEL_TEAM": TEAM_ID}
        ):
            session = VercelProvider.setup_session()

        assert session.team_id == TEAM_ID


class TestVercelProviderSetupIdentity:
    def test_setup_identity_with_team(self):
        mock_session = VercelSession(
            token=API_TOKEN, team_id=TEAM_ID, http_session=MagicMock()
        )

        # Mock user response
        user_response = MagicMock()
        user_response.status_code = 200
        user_response.json.return_value = {
            "user": {
                "id": USER_ID,
                "username": USERNAME,
                "email": USER_EMAIL,
            }
        }
        user_response.raise_for_status = MagicMock()

        # Mock team response
        team_response = MagicMock()
        team_response.status_code = 200
        team_response.json.return_value = {
            "id": TEAM_ID,
            "name": TEAM_NAME,
            "slug": TEAM_SLUG,
        }
        team_response.raise_for_status = MagicMock()

        def mock_get(url, **kwargs):
            if "/v2/user" in url:
                return user_response
            if f"/v2/teams/{TEAM_ID}" in url:
                return team_response
            return MagicMock()

        mock_session.http_session.get = mock_get

        identity = VercelProvider.setup_identity(mock_session)

        assert isinstance(identity, VercelIdentityInfo)
        assert identity.user_id == USER_ID
        assert identity.username == USERNAME
        assert identity.email == USER_EMAIL
        assert identity.team is not None
        assert identity.team.id == TEAM_ID
        assert identity.team.name == TEAM_NAME
        assert identity.team.slug == TEAM_SLUG

    def test_setup_identity_personal_account(self):
        mock_session = VercelSession(
            token=API_TOKEN, team_id=None, http_session=MagicMock()
        )

        user_response = MagicMock()
        user_response.status_code = 200
        user_response.json.return_value = {
            "user": {
                "id": USER_ID,
                "username": USERNAME,
                "email": USER_EMAIL,
            }
        }
        user_response.raise_for_status = MagicMock()

        mock_session.http_session.get = MagicMock(return_value=user_response)

        identity = VercelProvider.setup_identity(mock_session)

        assert identity.team is None
        assert identity.user_id == USER_ID


class TestVercelProviderValidateCredentials:
    def test_valid_credentials(self):
        mock_session = VercelSession(
            token=API_TOKEN, team_id=None, http_session=MagicMock()
        )

        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        mock_session.http_session.get = MagicMock(return_value=response)

        # Should not raise
        VercelProvider.validate_credentials(mock_session)

    def test_invalid_token_raises(self):
        mock_session = VercelSession(
            token="invalid", team_id=None, http_session=MagicMock()
        )

        response = MagicMock()
        response.status_code = 401
        mock_session.http_session.get = MagicMock(return_value=response)

        with pytest.raises(VercelAuthenticationError):
            VercelProvider.validate_credentials(mock_session)

    def test_forbidden_raises(self):
        mock_session = VercelSession(
            token=API_TOKEN, team_id=None, http_session=MagicMock()
        )

        response = MagicMock()
        response.status_code = 403
        mock_session.http_session.get = MagicMock(return_value=response)

        with pytest.raises(VercelAuthenticationError):
            VercelProvider.validate_credentials(mock_session)


class TestVercelProviderTestConnection:
    @patch.object(VercelProvider, "validate_credentials")
    @patch.object(VercelProvider, "setup_session")
    def test_successful_connection(self, mock_setup_session, mock_validate):
        mock_setup_session.return_value = VercelSession(
            token=API_TOKEN, team_id=None, http_session=MagicMock()
        )
        mock_validate.return_value = None

        result = VercelProvider.test_connection(raise_on_exception=False)

        assert isinstance(result, Connection)
        assert result.is_connected is True

    @patch.object(VercelProvider, "validate_credentials")
    @patch.object(VercelProvider, "setup_session")
    def test_successful_connection_with_params(self, mock_setup_session, mock_validate):
        mock_setup_session.return_value = VercelSession(
            token=API_TOKEN, team_id=TEAM_ID, http_session=MagicMock()
        )
        mock_validate.return_value = None

        result = VercelProvider.test_connection(
            api_token=API_TOKEN, team_id=TEAM_ID, raise_on_exception=False
        )

        assert isinstance(result, Connection)
        assert result.is_connected is True
        mock_setup_session.assert_called_once_with(api_token=API_TOKEN, team_id=TEAM_ID)

    @patch.object(VercelProvider, "setup_session")
    def test_failed_connection_no_credentials(self, mock_setup_session):
        mock_setup_session.side_effect = VercelCredentialsError(
            message="No credentials"
        )

        result = VercelProvider.test_connection(raise_on_exception=False)

        assert isinstance(result, Connection)
        assert result.is_connected is False
        assert result.error is not None

    @patch.object(VercelProvider, "setup_session")
    def test_failed_connection_raises(self, mock_setup_session):
        mock_setup_session.side_effect = VercelCredentialsError(
            message="No credentials"
        )

        with pytest.raises(VercelCredentialsError):
            VercelProvider.test_connection(raise_on_exception=True)
