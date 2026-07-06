from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.oraclecloud.exceptions.exceptions import (
    OCIAuthenticationError,
    OCIInvalidConfigError,
    OCISetUpSessionError,
)
from prowler.providers.oraclecloud.models import OCIIdentityInfo, OCIRegion, OCISession
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

    def test_test_connection_direct_credentials_without_region_uses_bootstrap_region(
        self,
    ):
        """Direct API key auth should not fall back to config-file auth without a region."""
        import base64

        valid_key = (
            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        )
        encoded_key = base64.b64encode(valid_key.encode("utf-8")).decode("utf-8")

        with (
            patch("oci.config.validate_config") as mock_validate_config,
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
                key_content=encoded_key,
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                provider_id="ocid1.tenancy.oc1..aaaaaaaexample",
                raise_on_exception=False,
            )

        assert connection.is_connected is True
        assert (
            mock_validate_config.call_args.args[0]["region"]
            == OraclecloudProvider._bootstrap_region
        )


class TestOraclecloudProviderInit:
    """Tests for OraclecloudProvider initialization"""

    def test_init_with_region_set_populates_provider_state(self):
        mock_session = OCISession(
            config={"region": "us-ashburn-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-ashburn-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        mock_regions = [
            OCIRegion(key="us-phoenix-1", name="us-phoenix-1", is_home_region=False),
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=True),
        ]
        mock_compartments = ["ocid1.compartment.oc1..aaaaaaaexample"]
        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=mock_regions,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=mock_compartments,
            ),
            patch(
                "prowler.providers.common.provider.Provider.set_global_provider"
            ) as mock_set_global,
        ):
            provider = OraclecloudProvider(
                region={"us-ashburn-1"},
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )
        assert mock_setup_session.call_args.kwargs["region"] == "us-ashburn-1"
        assert provider.session == mock_session
        assert provider.identity == mock_identity
        assert provider.regions == mock_regions
        assert provider.compartments == mock_compartments
        assert provider.home_region == "us-ashburn-1"
        mock_set_global.assert_called_once_with(provider)

    def test_init_with_multiple_regions_does_not_use_legacy_single_region_fallback(
        self,
    ):
        mock_session = OCISession(
            config={"region": "us-ashburn-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-ashburn-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        audited_regions = [
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=True),
            OCIRegion(key="us-phoenix-1", name="us-phoenix-1", is_home_region=False),
        ]
        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ) as mock_set_identity,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=audited_regions,
            ) as mock_get_regions_to_audit,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            provider = OraclecloudProvider(
                region={"us-phoenix-1", "us-ashburn-1"},
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                key_content="fake-base64-key-content",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert (
            mock_setup_session.call_args.kwargs["region"]
            == OraclecloudProvider._bootstrap_region
        )
        assert mock_set_identity.call_args.kwargs["region"] is None
        assert mock_get_regions_to_audit.call_args_list[0].args == (
            {"us-phoenix-1", "us-ashburn-1"},
        )
        assert provider.regions == audited_regions

    def test_init_with_legacy_region_string_uses_full_region_for_identity(self):
        mock_session = OCISession(
            config={"region": "us-ashburn-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-ashburn-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        audited_regions = [
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=True),
        ]

        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ) as mock_set_identity,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=audited_regions,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            OraclecloudProvider(
                region="us-ashburn-1",
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                key_content="fake-base64-key-content",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert mock_setup_session.call_args.kwargs["region"] == "us-ashburn-1"
        assert mock_set_identity.call_args.kwargs["region"] == "us-ashburn-1"

    def test_init_without_region_uses_direct_credentials_bootstrap_without_scan_filter(
        self,
    ):
        mock_session = OCISession(
            config={"region": "us-ashburn-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-ashburn-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        all_subscribed_regions = [
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=True),
            OCIRegion(key="us-phoenix-1", name="us-phoenix-1", is_home_region=False),
        ]

        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ) as mock_set_identity,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=all_subscribed_regions,
            ) as mock_get_regions_to_audit,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            provider = OraclecloudProvider(
                user="ocid1.user.oc1..aaaaaaaexample",
                fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                key_content="fake-base64-key-content",
                tenancy="ocid1.tenancy.oc1..aaaaaaaexample",
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert (
            mock_setup_session.call_args.kwargs["region"]
            == OraclecloudProvider._bootstrap_region
        )
        assert mock_set_identity.call_args.kwargs["region"] is None
        assert mock_get_regions_to_audit.call_args_list[0].args == (None,)
        assert provider.regions == all_subscribed_regions

    def test_init_with_config_file_auth_without_region_uses_session_config_region_for_identity(
        self,
    ):
        mock_session = OCISession(
            config={
                "tenancy": "ocid1.tenancy.oc1..aaaaaaaexample",
                "user": "ocid1.user.oc1..aaaaaaaexample",
                "region": "eu-frankfurt-1",
            },
            signer=None,
            profile="DEFAULT",
        )
        all_subscribed_regions = [
            OCIRegion(key="eu-frankfurt-1", name="eu-frankfurt-1", is_home_region=True),
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=False),
        ]

        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch("oci.identity.IdentityClient") as mock_identity_client,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=all_subscribed_regions,
            ) as mock_get_regions_to_audit,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"
            mock_identity_client.return_value.get_tenancy.return_value.data = (
                mock_tenancy
            )

            provider = OraclecloudProvider(
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert mock_setup_session.call_args.kwargs["region"] is None
        assert provider.identity.region == "eu-frankfurt-1"
        assert provider.identity.audited_regions == {"eu-frankfurt-1"}
        assert mock_get_regions_to_audit.call_args_list[0].args == (None,)
        assert provider.regions == all_subscribed_regions

    def test_init_with_instance_principal_without_region_uses_session_config_region_for_identity(
        self,
    ):
        mock_signer = MagicMock()
        mock_session = OCISession(
            config={
                "tenancy": "ocid1.tenancy.oc1..aaaaaaaexample",
                "region": "uk-london-1",
            },
            signer=mock_signer,
            profile=None,
        )
        all_subscribed_regions = [
            OCIRegion(key="uk-london-1", name="uk-london-1", is_home_region=True),
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=False),
        ]

        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ) as mock_setup_session,
            patch("oci.identity.IdentityClient") as mock_identity_client,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                return_value=all_subscribed_regions,
            ) as mock_get_regions_to_audit,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            mock_tenancy = MagicMock()
            mock_tenancy.name = "test-tenancy"
            mock_identity_client.return_value.get_tenancy.return_value.data = (
                mock_tenancy
            )

            provider = OraclecloudProvider(
                use_instance_principal=True,
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert mock_setup_session.call_args.kwargs["region"] is None
        assert provider.identity.region == "uk-london-1"
        assert provider.identity.user_id == "instance-principal"
        assert provider.identity.audited_regions == {"uk-london-1"}
        assert mock_get_regions_to_audit.call_args_list[0].args == (None,)
        assert provider.regions == all_subscribed_regions

    def test_home_region_uses_full_subscription_list_not_region_filter(self):
        """Home region must come from the full subscription list, not the --region filter.

        When auditing a single non-home region, the tenancy home region must still be
        resolved correctly so tenancy-level APIs (e.g. the Audit configuration) target it.
        """
        mock_session = OCISession(
            config={"region": "eu-frankfurt-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="eu-frankfurt-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        # The audited set is the non-home region; the full subscription list includes home
        audited_regions = [
            OCIRegion(
                key="eu-frankfurt-1", name="eu-frankfurt-1", is_home_region=False
            ),
        ]
        all_subscribed_regions = [
            OCIRegion(
                key="eu-frankfurt-1", name="eu-frankfurt-1", is_home_region=False
            ),
            OCIRegion(key="us-ashburn-1", name="us-ashburn-1", is_home_region=True),
        ]
        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_regions_to_audit",
                side_effect=[audited_regions, all_subscribed_regions],
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            provider = OraclecloudProvider(
                region={"eu-frankfurt-1"},
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert provider.regions == audited_regions
        assert provider.home_region == "us-ashburn-1"

    def test_init_with_legacy_single_region_preserves_fallback_for_home_region(self):
        mock_session = OCISession(
            config={"region": "us-phoenix-1"}, signer=None, profile="DEFAULT"
        )
        mock_identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-phoenix-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )

        with (
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.setup_session",
                return_value=mock_session,
            ),
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.set_identity",
                return_value=mock_identity,
            ),
            patch("oci.identity.IdentityClient") as mock_identity_client,
            patch(
                "prowler.providers.oraclecloud.oraclecloud_provider.OraclecloudProvider.get_compartments_to_audit",
                return_value=["ocid1.compartment.oc1..aaaaaaaexample"],
            ),
            patch("prowler.providers.common.provider.Provider.set_global_provider"),
        ):
            mock_identity_client.return_value.list_region_subscriptions.side_effect = (
                Exception("discovery failed")
            )

            provider = OraclecloudProvider(
                region="us-phoenix-1",
                config_content={"dummy": True},
                mutelist_content={"Accounts": {}},
            )

        assert [region.key for region in provider.regions] == ["us-phoenix-1"]
        assert provider.home_region == "us-phoenix-1"


class TestGetRegionsToAudit:
    def _provider_with_identity(self):
        provider = OraclecloudProvider.__new__(OraclecloudProvider)
        provider._session = OCISession(
            config={"region": "us-ashburn-1"}, signer=None, profile="DEFAULT"
        )
        provider._identity = OCIIdentityInfo(
            tenancy_id="ocid1.tenancy.oc1..aaaaaaaexample",
            tenancy_name="test-tenancy",
            user_id="ocid1.user.oc1..aaaaaaaexample",
            region="us-ashburn-1",
            profile="DEFAULT",
            audited_regions=set(),
            audited_compartments=[],
        )
        return provider

    def test_regionless_scan_raises_when_region_subscription_discovery_fails(self):
        provider = self._provider_with_identity()

        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_identity_client.return_value.list_region_subscriptions.side_effect = (
                Exception("discovery failed")
            )

            with pytest.raises(OCISetUpSessionError) as exc_info:
                provider.get_regions_to_audit()

        assert "Could not retrieve OCI subscribed regions" in str(exc_info.value)

    def test_single_explicit_region_falls_back_when_region_subscription_discovery_fails(
        self,
    ):
        provider = self._provider_with_identity()

        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_identity_client.return_value.list_region_subscriptions.side_effect = (
                Exception("discovery failed")
            )

            regions = provider.get_regions_to_audit("us-phoenix-1")

        assert len(regions) == 1
        assert regions[0].key == "us-phoenix-1"

    def test_multiple_explicit_regions_raise_when_region_subscription_discovery_fails(
        self,
    ):
        provider = self._provider_with_identity()

        with patch("oci.identity.IdentityClient") as mock_identity_client:
            mock_identity_client.return_value.list_region_subscriptions.side_effect = (
                Exception("discovery failed")
            )

            with pytest.raises(OCISetUpSessionError):
                provider.get_regions_to_audit({"us-ashburn-1", "us-phoenix-1"})
