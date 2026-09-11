import os
from unittest.mock import MagicMock, patch

import pytest
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from google.auth.impersonated_credentials import Credentials as ImpersonatedCredentials
from google.oauth2.service_account import Credentials
from googleapiclient.errors import HttpError

from prowler.providers.googleworkspace.exceptions.exceptions import (
    GoogleWorkspaceADCError,
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
    IMPERSONATED_SERVICE_ACCOUNT,
    ROOT_ORG_UNIT_ID,
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
            assert provider.domain_resource.id == CUSTOMER_ID
            assert provider.domain_resource.name == DOMAIN
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
            assert provider.domain_resource.customer_id == CUSTOMER_ID

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

    def test_setup_identity_fetches_root_org_unit(self):
        """Test that setup_identity fetches and stores the root org unit ID"""
        mock_session = GoogleWorkspaceSession(credentials=MagicMock(spec=Credentials))

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.build"
        ) as mock_build:
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.customers().get().execute.return_value = {"id": CUSTOMER_ID}
            mock_service.domains().list().execute.return_value = {
                "domains": [{"domainName": DOMAIN}]
            }
            mock_service.orgunits().list().execute.return_value = {
                "organizationUnits": [
                    {
                        "orgUnitPath": "/",
                        "orgUnitId": f"id:{ROOT_ORG_UNIT_ID}",
                        "name": "Test Company",
                    }
                ]
            }

            identity = GoogleworkspaceProvider.setup_identity(
                session=mock_session,
                delegated_user=DELEGATED_USER,
            )

            assert identity.root_org_unit_id == ROOT_ORG_UNIT_ID
            assert identity.customer_id == CUSTOMER_ID

    def test_setup_identity_root_org_unit_fetch_failure(self):
        """Test that setup_identity gracefully handles root org unit fetch failure"""
        mock_session = GoogleWorkspaceSession(credentials=MagicMock(spec=Credentials))

        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.build"
        ) as mock_build:
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.customers().get().execute.return_value = {"id": CUSTOMER_ID}
            mock_service.domains().list().execute.return_value = {
                "domains": [{"domainName": DOMAIN}]
            }
            mock_service.orgunits().list().execute.side_effect = Exception(
                "Insufficient permissions"
            )

            identity = GoogleworkspaceProvider.setup_identity(
                session=mock_session,
                delegated_user=DELEGATED_USER,
            )

            assert identity.root_org_unit_id is None
            assert identity.customer_id == CUSTOMER_ID

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

    def test_setup_session_impersonate_service_account(self):
        """Test keyless authentication through ADC + Service Account impersonation"""
        mock_source_credentials = MagicMock()
        mock_impersonated_credentials = MagicMock(spec=ImpersonatedCredentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default",
                return_value=(mock_source_credentials, None),
            ) as mock_default,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.impersonated_credentials.Credentials",
                return_value=mock_impersonated_credentials,
            ) as mock_impersonated_class,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.users().get().execute.return_value = {
                "primaryEmail": DELEGATED_USER
            }

            session, resolved_delegated_user = GoogleworkspaceProvider.setup_session(
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                delegated_user=DELEGATED_USER,
            )

            mock_default.assert_called_once()
            # The delegated user travels as the JWT subject of the impersonated
            # credentials, which google-auth signs through the IAM Credentials API.
            mock_impersonated_class.assert_called_once_with(
                source_credentials=mock_source_credentials,
                target_principal=IMPERSONATED_SERVICE_ACCOUNT,
                target_scopes=GoogleworkspaceProvider.SCOPES,
                subject=DELEGATED_USER,
            )
            assert session.credentials is mock_impersonated_credentials
            assert session.impersonated_service_account == IMPERSONATED_SERVICE_ACCOUNT
            assert resolved_delegated_user == DELEGATED_USER
            mock_build.assert_called_once_with(
                "admin",
                "directory_v1",
                credentials=mock_impersonated_credentials,
                cache_discovery=False,
            )

    def test_setup_session_impersonate_service_account_from_env(self):
        """Test GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT is used when no key is given"""
        mock_impersonated_credentials = MagicMock(spec=ImpersonatedCredentials)

        with (
            patch.dict(
                os.environ,
                {
                    "GOOGLEWORKSPACE_CREDENTIALS_FILE": "",
                    "GOOGLEWORKSPACE_CREDENTIALS_CONTENT": "",
                    "GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT": IMPERSONATED_SERVICE_ACCOUNT,
                    "GOOGLEWORKSPACE_DELEGATED_USER": DELEGATED_USER,
                },
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default",
                return_value=(MagicMock(), None),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.impersonated_credentials.Credentials",
                return_value=mock_impersonated_credentials,
            ) as mock_impersonated_class,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.return_value = {}

            session, resolved_delegated_user = GoogleworkspaceProvider.setup_session()

            assert mock_impersonated_class.call_args.kwargs["target_principal"] == (
                IMPERSONATED_SERVICE_ACCOUNT
            )
            assert mock_impersonated_class.call_args.kwargs["subject"] == DELEGATED_USER
            assert session.impersonated_service_account == IMPERSONATED_SERVICE_ACCOUNT
            assert resolved_delegated_user == DELEGATED_USER

    def test_setup_session_key_takes_precedence_over_impersonation(self):
        """Test Service Account key material wins when both a key and impersonation are given"""
        mock_credentials = MagicMock(spec=Credentials)
        mock_credentials.with_subject.return_value = MagicMock(spec=Credentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.service_account.Credentials.from_service_account_file",
                return_value=mock_credentials,
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default"
            ) as mock_default,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.return_value = {}

            session, _ = GoogleworkspaceProvider.setup_session(
                credentials_file="/path/to/creds.json",
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                delegated_user=DELEGATED_USER,
            )

            mock_default.assert_not_called()
            mock_credentials.with_subject.assert_called_once_with(DELEGATED_USER)
            assert session.impersonated_service_account is None

    def test_setup_session_env_key_takes_precedence_over_impersonation_flag(self):
        """Test GOOGLEWORKSPACE_CREDENTIALS_FILE wins over the --impersonate-service-account flag"""
        mock_credentials = MagicMock(spec=Credentials)
        mock_credentials.with_subject.return_value = MagicMock(spec=Credentials)

        with (
            patch.dict(
                os.environ,
                {
                    "GOOGLEWORKSPACE_CREDENTIALS_FILE": "/path/to/creds.json",
                    "GOOGLEWORKSPACE_CREDENTIALS_CONTENT": "",
                    "GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT": "",
                },
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.service_account.Credentials.from_service_account_file",
                return_value=mock_credentials,
            ) as mock_from_file,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default"
            ) as mock_default,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.return_value = {}

            session, _ = GoogleworkspaceProvider.setup_session(
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                delegated_user=DELEGATED_USER,
            )

            assert mock_from_file.call_args.args[0] == "/path/to/creds.json"
            mock_default.assert_not_called()
            mock_credentials.with_subject.assert_called_once_with(DELEGATED_USER)
            assert session.impersonated_service_account is None

    def test_setup_session_impersonation_flag_takes_precedence_over_env(self):
        """Test --impersonate-service-account wins over GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT"""
        mock_impersonated_credentials = MagicMock(spec=ImpersonatedCredentials)

        with (
            patch.dict(
                os.environ,
                {
                    "GOOGLEWORKSPACE_CREDENTIALS_FILE": "",
                    "GOOGLEWORKSPACE_CREDENTIALS_CONTENT": "",
                    "GOOGLEWORKSPACE_IMPERSONATE_SERVICE_ACCOUNT": "other-reader@test-project-12345.iam.gserviceaccount.com",
                },
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default",
                return_value=(MagicMock(), None),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.impersonated_credentials.Credentials",
                return_value=mock_impersonated_credentials,
            ) as mock_impersonated_class,
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.return_value = {}

            session, _ = GoogleworkspaceProvider.setup_session(
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                delegated_user=DELEGATED_USER,
            )

            assert mock_impersonated_class.call_args.kwargs["target_principal"] == (
                IMPERSONATED_SERVICE_ACCOUNT
            )
            assert session.impersonated_service_account == IMPERSONATED_SERVICE_ACCOUNT

    def test_setup_session_impersonation_without_adc(self):
        """Test GoogleWorkspaceADCError when Application Default Credentials are missing"""
        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.default",
            side_effect=DefaultCredentialsError(
                "Could not automatically determine credentials"
            ),
        ):
            with pytest.raises(GoogleWorkspaceADCError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                    delegated_user=DELEGATED_USER,
                )
            assert "Application Default Credentials could not be loaded" in str(
                exc_info.value
            )

    def test_setup_session_impersonation_invalid_service_account_email(self):
        """Test a malformed Service Account email is rejected before touching ADC"""
        with patch(
            "prowler.providers.googleworkspace.googleworkspace_provider.default"
        ) as mock_default:
            with pytest.raises(GoogleWorkspaceInvalidCredentialsError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    impersonate_service_account="not-a-service-account",
                    delegated_user=DELEGATED_USER,
                )
            assert "Invalid Service Account email format" in str(exc_info.value)
            mock_default.assert_not_called()

    def test_setup_session_impersonation_sign_jwt_denied(self):
        """Test the 403 hint mentions serviceAccountTokenCreator when impersonating"""
        mock_impersonated_credentials = MagicMock(spec=ImpersonatedCredentials)
        http_error = HttpError(
            resp=MagicMock(status=403), content=b"Forbidden", uri="test"
        )

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default",
                return_value=(MagicMock(), None),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.impersonated_credentials.Credentials",
                return_value=mock_impersonated_credentials,
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.side_effect = http_error

            with pytest.raises(GoogleWorkspaceInsufficientScopesError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                    delegated_user=DELEGATED_USER,
                )
            assert "roles/iam.serviceAccountTokenCreator" in str(exc_info.value)
            assert IMPERSONATED_SERVICE_ACCOUNT in str(exc_info.value)

    def test_googleworkspace_provider_print_credentials_impersonation(self):
        """Test print_credentials reports the keyless authentication method"""
        mock_credentials = MagicMock(spec=ImpersonatedCredentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=(
                    GoogleWorkspaceSession(
                        credentials=mock_credentials,
                        impersonated_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                    ),
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
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                delegated_user=DELEGATED_USER,
            )

            provider.print_credentials()

            report_lines = mock_print_boxes.call_args[0][0]
            assert any(
                "Application Default Credentials" in line
                and IMPERSONATED_SERVICE_ACCOUNT in line
                for line in report_lines
            )

    def test_test_connection_impersonate_service_account(self):
        """Test test_connection forwards impersonate_service_account to setup_session"""
        mock_credentials = MagicMock(spec=ImpersonatedCredentials)

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.GoogleworkspaceProvider.setup_session",
                return_value=(
                    GoogleWorkspaceSession(
                        credentials=mock_credentials,
                        impersonated_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                    ),
                    DELEGATED_USER,
                ),
            ) as mock_setup_session,
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
                delegated_user=DELEGATED_USER,
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
            )

            assert connection.is_connected is True
            mock_setup_session.assert_called_once_with(
                credentials_file=None,
                credentials_content=None,
                delegated_user=DELEGATED_USER,
                impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
            )

    def test_setup_session_impersonation_sign_jwt_permission_denied(self):
        """Test an IAM Credentials signJwt refusal (RefreshError) maps to the scopes error with the hint"""
        mock_impersonated_credentials = MagicMock(spec=ImpersonatedCredentials)
        # Shape raised by google.auth.impersonated_credentials._sign_jwt_request on a
        # non-200 response: RefreshError(_REFRESH_ERROR, <raw IAM Credentials API body>).
        sign_jwt_error = RefreshError(
            "Unable to acquire impersonated credentials",
            '{"error": {"code": 403, "message": "Permission \'iam.serviceAccounts.signJwt\' '
            'denied on resource (or it may not exist).", "status": "PERMISSION_DENIED"}}',
        )

        with (
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.default",
                return_value=(MagicMock(), None),
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.impersonated_credentials.Credentials",
                return_value=mock_impersonated_credentials,
            ),
            patch(
                "prowler.providers.googleworkspace.googleworkspace_provider.build"
            ) as mock_build,
        ):
            mock_build.return_value.users().get().execute.side_effect = sign_jwt_error

            with pytest.raises(GoogleWorkspaceInsufficientScopesError) as exc_info:
                GoogleworkspaceProvider.setup_session(
                    impersonate_service_account=IMPERSONATED_SERVICE_ACCOUNT,
                    delegated_user=DELEGATED_USER,
                )
            assert "roles/iam.serviceAccountTokenCreator" in str(exc_info.value)
