from unittest.mock import MagicMock, patch

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_REGION,
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class TestAuditService:
    def test_service(self):
        """Test that audit service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.audit.audit_service.Audit.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.audit.audit_service import Audit

            audit_client = Audit(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            audit_client.service = "audit"
            audit_client.provider = oraclecloud_provider
            audit_client.audited_compartments = {}
            audit_client.regional_clients = {}

            # Verify service name
            assert audit_client.service == "audit"
            assert audit_client.provider == oraclecloud_provider

    def test_get_configuration_uses_home_region(self):
        """Test that AuditClient is created with the home region config override."""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the OCI AuditClient and its get_configuration response
        mock_config_response = MagicMock()
        mock_config_response.data.retention_period_days = 365

        mock_audit_client = MagicMock()
        mock_audit_client.get_configuration.return_value = mock_config_response

        with patch(
            "prowler.providers.oraclecloud.services.audit.audit_service.Audit.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.audit.audit_service import Audit

            audit = Audit(oraclecloud_provider)

            # Set required attributes that __init__ would normally set
            audit.provider = oraclecloud_provider
            audit.audited_tenancy = OCI_TENANCY_ID
            audit.session_config = oraclecloud_provider.session.config
            audit.session_signer = oraclecloud_provider.session.signer
            audit.configuration = None

            # Mock _create_oci_client to capture what it's called with
            audit._create_oci_client = MagicMock(return_value=mock_audit_client)

            # Call the method under test
            audit.__get_configuration__()

            # Verify _create_oci_client was called with the home region override
            import oci

            audit._create_oci_client.assert_called_once_with(
                oci.audit.AuditClient,
                config_overrides={"region": OCI_REGION},
            )

            # Verify the configuration was set correctly
            assert audit.configuration is not None
            assert audit.configuration.retention_period_days == 365
            assert audit.configuration.compartment_id == OCI_TENANCY_ID

    def test_get_configuration_handles_api_error(self):
        """Test that API errors still default to 90-day retention."""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        mock_audit_client = MagicMock()
        mock_audit_client.get_configuration.side_effect = Exception("404 Not Found")

        with patch(
            "prowler.providers.oraclecloud.services.audit.audit_service.Audit.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.audit.audit_service import Audit

            audit = Audit(oraclecloud_provider)

            # Set required attributes
            audit.provider = oraclecloud_provider
            audit.audited_tenancy = OCI_TENANCY_ID
            audit.session_config = oraclecloud_provider.session.config
            audit.session_signer = oraclecloud_provider.session.signer
            audit.configuration = None

            audit._create_oci_client = MagicMock(return_value=mock_audit_client)

            # Call the method under test
            audit.__get_configuration__()

            # Verify it defaults to 90 days on error
            assert audit.configuration is not None
            assert audit.configuration.retention_period_days == 90
