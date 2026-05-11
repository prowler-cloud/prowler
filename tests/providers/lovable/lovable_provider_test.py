import os
from unittest import mock
from unittest.mock import MagicMock

import pytest

from prowler.providers.common.models import Connection
from prowler.providers.lovable.exceptions.exceptions import (
    LovableAuthenticationError,
    LovableCredentialsError,
)
from prowler.providers.lovable.lovable_provider import LovableProvider
from prowler.providers.lovable.models import LovableSession
from tests.providers.lovable.lovable_fixtures import API_TOKEN, WORKSPACE_ID


class TestLovableProviderSetupSession:
    def test_setup_session_with_env_var(self):
        with mock.patch.dict(os.environ, {"LOVABLE_API_TOKEN": API_TOKEN}, clear=True):
            session = LovableProvider.setup_session()

        assert isinstance(session, LovableSession)
        assert session.api_token == API_TOKEN
        assert session.http_session is not None

    def test_setup_session_with_arguments(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            session = LovableProvider.setup_session(
                api_token=API_TOKEN, workspace_id=WORKSPACE_ID
            )
        assert session.api_token == API_TOKEN
        assert session.workspace_id == WORKSPACE_ID

    def test_setup_session_no_credentials_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("LOVABLE_API_TOKEN", None)
            with pytest.raises(LovableCredentialsError):
                LovableProvider.setup_session()

    def test_setup_session_workspace_from_env(self):
        with mock.patch.dict(
            os.environ,
            {"LOVABLE_API_TOKEN": API_TOKEN, "LOVABLE_WORKSPACE_ID": WORKSPACE_ID},
            clear=True,
        ):
            session = LovableProvider.setup_session()
        assert session.workspace_id == WORKSPACE_ID


class TestLovableProviderTestConnection:
    def test_test_connection_success(self):
        with (
            mock.patch(
                "prowler.providers.lovable.lovable_provider.LovableProvider.setup_session"
            ) as session_mock,
            mock.patch(
                "prowler.providers.lovable.lovable_provider.LovableProvider.validate_credentials"
            ) as validate_mock,
        ):
            session_mock.return_value = MagicMock()
            validate_mock.return_value = None

            result = LovableProvider.test_connection(api_token=API_TOKEN)

        assert isinstance(result, Connection)
        assert result.is_connected is True

    def test_test_connection_no_credentials_returns_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            result = LovableProvider.test_connection(raise_on_exception=False)

        assert isinstance(result, Connection)
        assert result.is_connected is False
        assert isinstance(result.error, LovableCredentialsError)

    def test_test_connection_raises_on_invalid_token(self):
        with (
            mock.patch(
                "prowler.providers.lovable.lovable_provider.LovableProvider.setup_session"
            ) as session_mock,
            mock.patch(
                "prowler.providers.lovable.lovable_provider.LovableProvider.validate_credentials",
                side_effect=LovableAuthenticationError(file=__file__),
            ),
        ):
            session_mock.return_value = MagicMock()
            with pytest.raises(LovableAuthenticationError):
                LovableProvider.test_connection(
                    api_token=API_TOKEN, raise_on_exception=True
                )
