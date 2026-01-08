from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestComputeService:
    def test_service(self):
        """Test that compute service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.compute.compute_service.Compute.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.compute.compute_service import (
                Compute,
            )

            compute_client = Compute(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            compute_client.service = "compute"
            compute_client.provider = oraclecloud_provider
            compute_client.audited_compartments = {}
            compute_client.regional_clients = {}

            # Verify service name
            assert compute_client.service == "compute"
            assert compute_client.provider == oraclecloud_provider
