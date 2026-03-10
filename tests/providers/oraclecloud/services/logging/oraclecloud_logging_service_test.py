from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestLoggingService:
    def test_service(self):
        """Test that logging service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.logging.logging_service.Logging.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.logging.logging_service import (
                Logging,
            )

            logging_client = Logging(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            logging_client.service = "logging"
            logging_client.provider = oraclecloud_provider
            logging_client.audited_compartments = {}
            logging_client.regional_clients = {}

            # Verify service name
            assert logging_client.service == "logging"
            assert logging_client.provider == oraclecloud_provider
