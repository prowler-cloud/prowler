from unittest.mock import MagicMock, patch

import pytest
from google.oauth2.service_account import Credentials

from prowler.providers.googleworkspace.exceptions.exceptions import (
    GoogleWorkspaceMissingDelegatedUserError,
    GoogleWorkspaceNoCredentialsError,
    GoogleWorkspaceSetUpSessionError,
)
from prowler.providers.googleworkspace.googleworkspace_provider import (
    GoogleworkspaceProvider,
)
from prowler.providers.googleworkspace.models import (
    GoogleWorkspaceIdentityInfo,
    GoogleWorkspaceSession,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DELEGATED_USER,
    DOMAIN,
    SERVICE_ACCOUNT_CREDENTIALS,
)


class TestGoogleWorkspaceProvider:
    def test_googleworkspace_provider_with_credentials_file(self):
        """Test provider initialization with credentials file"""
        credentials_file = "/path/to/credentials.json"
        delegated_user = DELEGATED_USER

        # Mock credentials object
        mock_credentials = MagicMock(spec=Credentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=GoogleWorkspaceSession(credentials=mock_credentials),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_identity",
                return_value=GoogleWorkspaceIdentityInfo(
                    domain=DOMAIN,
                    customer_id=CUSTOMER_ID,
                    delegated_user=DELEGATED_USER,
                    profile="default",
                ),
            ),
        ):
            provider = GoogleworkspaceProvider(
                credentials_file=credentials_file,
                delegated_user=delegated_user,
            )

            assert provider._type == "googleworkspace"
            assert provider.session.credentials == mock_credentials
            assert provider.identity == GoogleWorkspaceIdentityInfo(
                domain=DOMAIN,
                customer_id=CUSTOMER_ID,
                delegated_user=DELEGATED_USER,
                profile="default",
            )
            assert provider._audit_config == {}

    def test_googleworkspace_provider_with_credentials_content(self):
        """Test provider initialization with credentials content"""
        import json

        credentials_content = json.dumps(SERVICE_ACCOUNT_CREDENTIALS)
        delegated_user = DELEGATED_USER

        # Mock credentials object
        mock_credentials = MagicMock(spec=Credentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=GoogleWorkspaceSession(credentials=mock_credentials),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_identity",
                return_value=GoogleWorkspaceIdentityInfo(
                    domain=DOMAIN,
                    customer_id=CUSTOMER_ID,
                    delegated_user=DELEGATED_USER,
                    profile="default",
                ),
            ),
        ):
            provider = GoogleworkspaceProvider(
                credentials_content=credentials_content,
                delegated_user=delegated_user,
            )

            assert provider._type == "googleworkspace"
            assert provider.identity.domain == DOMAIN
            assert provider.identity.customer_id == CUSTOMER_ID
            assert provider.identity.delegated_user == DELEGATED_USER

    def test_googleworkspace_provider_missing_delegated_user(self):
        """Test that missing delegated_user raises exception"""
        credentials_file = "/path/to/credentials.json"

        with pytest.raises(GoogleWorkspaceMissingDelegatedUserError):
            GoogleworkspaceProvider.setup_session(
                credentials_file=credentials_file,
                delegated_user=None,
            )

    def test_googleworkspace_provider_no_credentials(self):
        """Test that missing credentials raises exception"""
        delegated_user = DELEGATED_USER

        with pytest.raises(GoogleWorkspaceNoCredentialsError):
            GoogleworkspaceProvider.setup_session(
                credentials_file=None,
                credentials_content=None,
                delegated_user=delegated_user,
            )

    def test_googleworkspace_provider_test_connection_success(self):
        """Test successful connection test"""
        credentials_file = "/path/to/credentials.json"
        delegated_user = DELEGATED_USER

        mock_credentials = MagicMock(spec=Credentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=GoogleWorkspaceSession(credentials=mock_credentials),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_identity",
                return_value=GoogleWorkspaceIdentityInfo(
                    domain=DOMAIN,
                    customer_id=CUSTOMER_ID,
                    delegated_user=DELEGATED_USER,
                    profile="default",
                ),
            ),
        ):
            connection = GoogleworkspaceProvider.test_connection(
                credentials_file=credentials_file,
                delegated_user=delegated_user,
            )

            assert connection.is_connected is True
            assert connection.error is None

    def test_googleworkspace_provider_test_connection_failure(self):
        """Test failed connection test"""
        credentials_file = "/path/to/credentials.json"
        delegated_user = DELEGATED_USER

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
            side_effect=GoogleWorkspaceSetUpSessionError(),
        ):
            connection = GoogleworkspaceProvider.test_connection(
                credentials_file=credentials_file,
                delegated_user=delegated_user,
                raise_on_exception=False,
            )

            assert connection.is_connected is False
            assert connection.error is not None

    def test_googleworkspace_provider_print_credentials(self):
        """Test print_credentials method"""
        mock_credentials = MagicMock(spec=Credentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=GoogleWorkspaceSession(credentials=mock_credentials),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_identity",
                return_value=GoogleWorkspaceIdentityInfo(
                    domain=DOMAIN,
                    customer_id=CUSTOMER_ID,
                    delegated_user=DELEGATED_USER,
                    profile="default",
                ),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.print_boxes"
            ) as mock_print_boxes,
        ):
            provider = GoogleworkspaceProvider(
                credentials_file="/path/to/credentials.json",
                delegated_user=DELEGATED_USER,
            )

            provider.print_credentials()

            # Verify print_boxes was called
            assert mock_print_boxes.called
