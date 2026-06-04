from unittest.mock import MagicMock, patch

import oci

from tests.providers.oraclecloud.oci_fixtures import (
    OCI_TENANCY_ID,
    set_mocked_oraclecloud_provider,
)


class TestAuditService:
    def test_service(self):
        """Test that audit service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        mock_config_response = MagicMock()
        mock_config_response.data.retention_period_days = 365

        mock_audit_client = MagicMock()
        mock_audit_client.get_configuration.return_value = mock_config_response

        from prowler.providers.oraclecloud.services.audit.audit_service import Audit

        with patch.object(Audit, "_create_oci_client", return_value=mock_audit_client):
            audit_client = Audit(oraclecloud_provider)

            assert audit_client.service == "audit"
            assert audit_client.provider == oraclecloud_provider

    def test_get_configuration_uses_home_region_not_configured_region(self):
        """Test Audit uses the tenancy home region instead of the configured region."""
        oraclecloud_provider = set_mocked_oraclecloud_provider(region="eu-frankfurt-1")
        # The tenancy home region differs from the configured session region
        oraclecloud_provider.home_region = "us-ashburn-1"
        mock_config_response = MagicMock()
        mock_config_response.data.retention_period_days = 365

        mock_audit_client = MagicMock()
        mock_audit_client.get_configuration.return_value = mock_config_response

        from prowler.providers.oraclecloud.services.audit.audit_service import Audit

        with patch.object(
            Audit, "_create_oci_client", return_value=mock_audit_client
        ) as mock_create_oci_client:
            audit = Audit(oraclecloud_provider)

            mock_create_oci_client.assert_called_once_with(
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

        from prowler.providers.oraclecloud.services.audit.audit_service import Audit

        with patch.object(Audit, "_create_oci_client", return_value=mock_audit_client):
            audit = Audit(oraclecloud_provider)

            assert audit.configuration is not None
            assert audit.configuration.retention_period_days == 90
            assert audit.configuration.compartment_id == OCI_TENANCY_ID
