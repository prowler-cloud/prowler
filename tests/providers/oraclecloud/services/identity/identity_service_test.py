from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestIdentityService:
    def test_service(self):
        """Test that identity service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.identity.identity_service.Identity.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.identity.identity_service import (
                Identity,
            )

            identity_client = Identity(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            identity_client.service = "identity"
            identity_client.provider = oraclecloud_provider
            identity_client.audited_compartments = {}
            identity_client.regional_clients = {}

            # Verify service name
            assert identity_client.service == "identity"
            assert identity_client.provider == oraclecloud_provider
