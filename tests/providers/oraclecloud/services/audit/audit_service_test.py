from unittest.mock import MagicMock, patch

from tests.providers.oraclecloud.oci_fixtures import (
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

    def test_get_configuration_uses_home_region_not_configured_region(self):
        """Test Audit uses the tenancy home region instead of the configured region."""
        oraclecloud_provider = set_mocked_oraclecloud_provider(
            region="eu-frankfurt-1",
            home_region="us-ashburn-1",
        )
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
            audit.provider = oraclecloud_provider
            audit.audited_tenancy = OCI_TENANCY_ID
            audit.session_config = oraclecloud_provider.session.config
            audit.session_signer = oraclecloud_provider.session.signer
            audit.configuration = None
            audit._create_oci_client = MagicMock(return_value=mock_audit_client)

            audit.__get_configuration__()
            import oci

            audit._create_oci_client.assert_called_once_with(
                oci.audit.AuditClient,
                config_overrides={"region": "us-ashburn-1"},
            )
            assert audit.configuration is not None
            assert audit.configuration.retention_period_days == 365
            assert audit.configuration.compartment_id == OCI_TENANCY_ID

    def test_get_configuration_handles_api_error(self):
        """Test audit configuration falls back to 90 days on API errors."""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        mock_audit_client = MagicMock()
        mock_audit_client.get_configuration.side_effect = Exception("404 Not Found")

        with patch(
            "prowler.providers.oraclecloud.services.audit.audit_service.Audit.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.audit.audit_service import Audit

            audit = Audit(oraclecloud_provider)
            audit.provider = oraclecloud_provider
            audit.audited_tenancy = OCI_TENANCY_ID
            audit.session_config = oraclecloud_provider.session.config
            audit.session_signer = oraclecloud_provider.session.signer
            audit.configuration = None
            audit._create_oci_client = MagicMock(return_value=mock_audit_client)

            audit.__get_configuration__()

            assert audit.configuration is not None
            assert audit.configuration.retention_period_days == 90
            assert audit.configuration.compartment_id == OCI_TENANCY_ID
