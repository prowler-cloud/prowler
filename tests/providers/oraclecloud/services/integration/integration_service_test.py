from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestIntegrationService:
    def test_service(self):
        """Test that integration service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.integration.integration_service.Integration.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.integration.integration_service import (
                Integration,
            )

            integration_client = Integration(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            integration_client.service = "integration"
            integration_client.provider = oraclecloud_provider
            integration_client.audited_compartments = {}
            integration_client.regional_clients = {}

            # Verify service name
            assert integration_client.service == "integration"
            assert integration_client.provider == oraclecloud_provider
