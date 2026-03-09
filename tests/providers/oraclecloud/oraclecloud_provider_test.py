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
