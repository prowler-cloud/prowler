from unittest.mock import MagicMock, patch

import pytest
from google.oauth2.service_account import Credentials
from googleapiclient.errors import HttpError

from prowler.providers.googleworkspace.exceptions.exceptions import (
    GoogleWorkspaceImpersonationError,
    GoogleWorkspaceInsufficientScopesError,
    GoogleWorkspaceInvalidCredentialsError,
    GoogleWorkspaceMissingDelegatedUserError,
    GoogleWorkspaceNoCredentialsError,
    GoogleWorkspaceSetUpIdentityError,
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
                return_value=(
                    GoogleWorkspaceSession(credentials=mock_credentials),
                    DELEGATED_USER,
                ),
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
                return_value=(
                    GoogleWorkspaceSession(credentials=mock_credentials),
                    DELEGATED_USER,
                ),
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
                return_value=(
                    GoogleWorkspaceSession(credentials=mock_credentials),
                    DELEGATED_USER,
                ),
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
                return_value=(
                    GoogleWorkspaceSession(credentials=mock_credentials),
                    DELEGATED_USER,
                ),
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

    def test_setup_session_credentials_file_invalid_json(self):
        """Test ValueError when credentials file has invalid format"""
        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.service_account.Credentials.from_service_account_file",
            side_effect=ValueError("Invalid credentials format"),
        ):
            with pytest.raises(GoogleWorkspaceInvalidCredentialsError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    credentials_file="/path/to/invalid.json",
                    delegated_user=DELEGATED_USER,
                )
            assert "Invalid service account credentials file" in str(exc_info.value)

    def test_setup_session_credentials_content_invalid_json(self):
        """Test JSONDecodeError when credentials content is invalid JSON"""
        with pytest.raises(GoogleWorkspaceInvalidCredentialsError) as exc_info:
            GoogleworkspaceProvider.setup_session(
                credentials_content="{ invalid json }",
                delegated_user=DELEGATED_USER,
            )
        assert "Invalid JSON in credentials content" in str(exc_info.value)

    def test_setup_session_invalid_delegated_user_email(self):
        """Test invalid delegated user email format"""
        with pytest.raises(GoogleWorkspaceInvalidCredentialsError) as exc_info:
            GoogleworkspaceProvider.setup_session(
                credentials_file="/path/to/credentials.json",
                delegated_user="not-an-email",
            )
        assert "Must be a valid email address" in str(exc_info.value)

    def test_setup_session_insufficient_scopes_403(self):
        """Test GoogleWorkspaceInsufficientScopesError for 403 errors"""
        mock_credentials = MagicMock(spec=Credentials)
        mock_delegated_creds = MagicMock()
        mock_credentials.with_subject.return_value = mock_delegated_creds

        # Mock HttpError with 403 status
        http_error = HttpError(
            resp=MagicMock(status=403), content=b"Forbidden", uri="test"
        )

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.service_account.Credentials.from_service_account_file",
                return_value=mock_credentials,
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.users().get().execute.side_effect = http_error

            with pytest.raises(GoogleWorkspaceInsufficientScopesError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    credentials_file="/path/to/creds.json",
                    delegated_user=DELEGATED_USER,
                )
            assert "Domain-Wide Delegation is not configured" in str(exc_info.value)

    def test_setup_session_impersonation_generic_error(self):
        """Test GoogleWorkspaceImpersonationError for other delegation errors"""
        mock_credentials = MagicMock(spec=Credentials)
        mock_delegated_creds = MagicMock()
        mock_credentials.with_subject.return_value = mock_delegated_creds

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.service_account.Credentials.from_service_account_file",
                return_value=mock_credentials,
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.users().get().execute.side_effect = Exception(
                "Connection error"
            )

            with pytest.raises(GoogleWorkspaceImpersonationError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    credentials_file="/path/to/creds.json",
                    delegated_user=DELEGATED_USER,
                )
            assert "Failed to verify delegation" in str(exc_info.value)

    def test_setup_identity_customer_fetch_failure(self):
        """Test error when fetching customer information fails"""
        mock_session = GoogleWorkspaceSession(credentials=MagicMock(spec=Credentials))

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.build"
        ) as mock_build:
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.customers().get().execute.side_effect = Exception("API error")

            with pytest.raises(GoogleWorkspaceSetUpIdentityError) as exc_info:
                GoogleworkspaceProvider.setup_identity(
                    session=mock_session,
                    delegated_user=DELEGATED_USER,
                )
            assert "Failed to fetch customer information" in str(exc_info.value)

    def test_setup_identity_domain_mismatch(self):
        """Test error when user domain is not in workspace"""
        mock_session = GoogleWorkspaceSession(credentials=MagicMock(spec=Credentials))

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.build"
        ) as mock_build:
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.customers().get().execute.return_value = {"id": CUSTOMER_ID}
            mock_service.domains().list().execute.return_value = {
                "domains": [{"domainName": "different-company.com"}]
            }

            with pytest.raises(GoogleWorkspaceInvalidCredentialsError) as exc_info:
                GoogleworkspaceProvider.setup_identity(
                    session=mock_session,
                    delegated_user=DELEGATED_USER,
                )
            assert "is not configured in this Google Workspace" in str(exc_info.value)

    def test_test_connection_raises_exception_when_flag_true(self):
        """Test that test_connection raises exception when raise_on_exception=True"""
        credentials_file = "/path/to/credentials.json"
        delegated_user = DELEGATED_USER

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
            side_effect=GoogleWorkspaceSetUpSessionError(
                file="test", message="Test error"
            ),
        ):
            with pytest.raises(GoogleWorkspaceSetUpSessionError):
                GoogleworkspaceProvider.test_connection(
                    credentials_file=credentials_file,
                    delegated_user=delegated_user,
                    raise_on_exception=True,
                )
