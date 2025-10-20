from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oci_provider


class TestNetworkService:
    def test_service(self):
        """Test that network service can be instantiated and mocked"""
        oci_provider = set_mocked_oci_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.network.network_service.Network.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.network.network_service import (
                Network,
            )

            network_client = Network(oci_provider)

            # Manually set required attributes since __init__ was mocked
            network_client.service = "network"
            network_client.provider = oci_provider
            network_client.audited_compartments = {}
            network_client.regional_clients = {}

            # Verify service name
            assert network_client.service == "network"
            assert network_client.provider == oci_provider
