from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.oraclecloud.exceptions.exceptions import (
    OCIAuthenticationError,
    OCIInvalidConfigError,
)
from prowler.providers.oraclecloud.models import OCISession
from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider


class TestSetIdentityAuthenticationErrors:
    """Tests for authentication error handling in set_identity()"""

    @pytest.fixture
    def mock_session(self):
        """Create a mock OCI session."""
        session = OCISession(
            config={
                "tenancy": "ocid1.tenancy.oc1..aaaaaaaexample",
                "user": "ocid1.user.oc1..aaaaaaaexample",
                "region": "us-ashburn-1",
                "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            },
            signer=None,
            profile="DEFAULT",
        )
        return session

    def test_authentication_error_401_raises_exception(self, mock_session):
        """Test 401 error raises OCIAuthenticationError."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = self._create_service_error(
                401, "Authentication failed"
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "OCI credential validation failed" in str(exc_info.value)

    def test_authentication_error_403_raises_exception(self, mock_session):
        """Test 403 error raises OCIAuthenticationError."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = self._create_service_error(
                403, "Forbidden access"
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "OCI credential validation failed" in str(exc_info.value)

    def test_authentication_error_404_raises_exception(self, mock_session):
        """Test 404 error raises OCIAuthenticationError."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = self._create_service_error(
                404, "Resource not found"
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "OCI credential validation failed" in str(exc_info.value)

    def test_service_error_500_raises_exception(self, mock_session):
        """Test 500 error raises OCIAuthenticationError (can't validate credentials)."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = self._create_service_error(
                500, "Internal server error"
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "OCI credential validation failed" in str(exc_info.value)

    def test_invalid_private_key_raises_exception(self, mock_session):
        """Test InvalidPrivateKey exception raises OCIAuthenticationError."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            import oci

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = (
                oci.exceptions.InvalidPrivateKey("Invalid private key")
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "Invalid OCI private key format" in str(exc_info.value)

    def test_generic_exception_raises_authentication_error(self, mock_session):
        """Test generic exception raises OCIAuthenticationError."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.side_effect = Exception("Unexpected error")
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(OCIAuthenticationError) as exc_info:
                OraclecloudProvider.set_identity(mock_session)

            assert "Failed to authenticate with OCI" in str(exc_info.value)

    def test_successful_authentication(self, mock_session):
        """Test successful authentication returns identity info."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"
            mock_response = MagicMock()
            mock_response.data = mock_tenancy

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.return_value = mock_response
            mock_identity_client.return_value = mock_client_instance

            identity = OraclecloudProvider.set_identity(mock_session)

            assert identity.tenancy_name == "test-tenancy"
            assert identity.tenancy_id == "ocid1.tenancy.oc1..aaaaaaaexample"
            assert identity.user_id == "ocid1.user.oc1..aaaaaaaexample"
            assert identity.region == "us-ashburn-1"

    def test_successful_authentication_persists_home_region_separately(
        self, mock_session
    ):
        """Test the tenancy home region is stored separately from the session region."""
        mock_session.config["region"] = "eu-frankfurt-1"

        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"

            home_region_subscription = MagicMock()
            home_region_subscription.region_name = "us-ashburn-1"
            home_region_subscription.is_home_region = True

            secondary_region_subscription = MagicMock()
            secondary_region_subscription.region_name = "eu-frankfurt-1"
            secondary_region_subscription.is_home_region = False

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.return_value = MagicMock(data=mock_tenancy)
            mock_client_instance.list_region_subscriptions.return_value = MagicMock(
                data=[secondary_region_subscription, home_region_subscription]
            )
            mock_identity_client.return_value = mock_client_instance

            identity = OraclecloudProvider.set_identity(mock_session)

            assert identity.region == "eu-frankfurt-1"
            assert identity.home_region == "us-ashburn-1"
            assert identity.region_subscriptions == [
                secondary_region_subscription,
                home_region_subscription,
            ]
            mock_client_instance.list_region_subscriptions.assert_called_once_with(
                "ocid1.tenancy.oc1..aaaaaaaexample"
            )

    def test_successful_authentication_logs_when_home_region_lookup_fails(
        self, mock_session
    ):
        """Test expected OCI errors during home region lookup are visible."""
        import oci

        with (
            patch("oci.identity.IdentityClient") as mock_identity_client,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.logger"
            ) as mock_logger,
        ):
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.return_value = MagicMock(data=mock_tenancy)
            mock_client_instance.list_region_subscriptions.side_effect = (
                oci.exceptions.ClientError("client error")
            )
            mock_identity_client.return_value = mock_client_instance

            identity = OraclecloudProvider.set_identity(mock_session)

            assert identity.region == "us-ashburn-1"
            assert identity.home_region == "us-ashburn-1"
            assert identity.region_subscriptions == []
            mock_logger.warning.assert_called_once()
            warning_message = mock_logger.warning.call_args.args[0]
            assert "Audit configuration checks" in warning_message
            assert "return 404" in warning_message

    def test_home_region_lookup_does_not_swallow_unexpected_errors(self, mock_session):
        """Test unexpected home region lookup errors are not hidden."""
        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.return_value = MagicMock(data=mock_tenancy)
            mock_client_instance.list_region_subscriptions.side_effect = ValueError(
                "bad region subscription shape"
            )
            mock_identity_client.return_value = mock_client_instance

            with pytest.raises(ValueError, match="bad region subscription shape"):
                OraclecloudProvider.set_identity(mock_session)

    def test_get_regions_to_audit_reuses_cached_region_subscriptions(self):
        """Test subscribed regions are reused from identity instead of fetched again."""
        home_region_subscription = MagicMock()
        home_region_subscription.region_name = "us-ashburn-1"
        home_region_subscription.is_home_region = True

        secondary_region_subscription = MagicMock()
        secondary_region_subscription.region_name = "eu-frankfurt-1"
        secondary_region_subscription.is_home_region = False

        provider = OraclecloudProvider.__new__(OraclecloudProvider)
        provider._identity = MagicMock(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            region_subscriptions=[
                home_region_subscription,
                secondary_region_subscription,
            ],
        )
        provider._session = MagicMock()

        with patch("oci.identity.IdentityClient") as mock_identity_client:
            regions = provider.get_regions_to_audit()

            mock_identity_client.assert_not_called()
            assert [region.key for region in regions] == [
                "us-ashburn-1",
                "eu-frankfurt-1",
            ]
            assert [region.is_home_region for region in regions] == [True, False]

    @staticmethod
    def _create_service_error(status, message):
        """Helper to create an OCI ServiceError."""
        import oci

        error = oci.exceptions.ServiceError(
            status=status,
            code="TestError",
            headers={},
            message=message,
        )
        return error


class TestTestConnectionKeyValidation:
    """Tests for key_content validation in test_connection()"""

    def test_test_connection_invalid_base64_key_raises_error(self):
        """Test invalid base64 key content raises OCIInvalidConfigError."""
        with pytest.raises(OCIInvalidConfigError) as exc_info:
            OraclecloudProvider.test_connection(
                oci_config_file=None,
                profile=None,
                key_content="not-valid-base64!!!",
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                region="us-ashburn-1",
            )

        assert "Failed to decode key_content" in str(exc_info.value)

    def test_test_connection_valid_key_content_proceeds(self):
        """Test valid base64 key content proceeds to authentication."""
        import base64

        # The SDK will validate the actual key format during authentication
        valid_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8n0sMcD/QHWCJ7yGSEtLN2T
...key content...
-----END RSA PRIVATE KEY-----"""
        encoded_key = base64.b64encode(valid_key.encode("utf-8")).decode("utf-8")

        with (
            patch("oci.config.validate_config"),
            patch("oci.identity.IdentityClient") as mock_identity_client,
        ):
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"
            mock_response = MagicMock()
            mock_response.data = mock_tenancy

            mock_client_instance = MagicMock()
            mock_client_instance.get_tenancy.return_value = mock_response
            mock_identity_client.return_value = mock_client_instance

            connection = OraclecloudProvider.test_connection(
                oci_config_file=None,
                profile=None,
                key_content=encoded_key,
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                region="us-ashburn-1",
                raise_on_exception=False,
            )

            assert connection.is_connected is True
