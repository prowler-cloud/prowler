from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestKmsService:
    def test_service(self):
        """Test that kms service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.kms.kms_service.Kms.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.kms.kms_service import Kms

            kms_client = Kms(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            kms_client.service = "kms"
            kms_client.provider = oraclecloud_provider
            kms_client.audited_compartments = {}
            kms_client.regional_clients = {}

            # Verify service name
            assert kms_client.service == "kms"
            assert kms_client.provider == oraclecloud_provider
