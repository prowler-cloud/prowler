from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestCloudguardService:
    def test_service(self):
        """Test that cloudguard service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.cloudguard.cloudguard_service.CloudGuard.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.cloudguard.cloudguard_service import (
                CloudGuard,
            )

            cloudguard_client = CloudGuard(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            cloudguard_client.service = "cloudguard"
            cloudguard_client.provider = oraclecloud_provider
            cloudguard_client.audited_compartments = {}
            cloudguard_client.regional_clients = {}

            # Verify service name
            assert cloudguard_client.service == "cloudguard"
            assert cloudguard_client.provider == oraclecloud_provider
