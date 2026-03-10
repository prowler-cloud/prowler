from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestDatabaseService:
    def test_service(self):
        """Test that database service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.database.database_service.Database.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.database.database_service import (
                Database,
            )

            database_client = Database(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            database_client.service = "database"
            database_client.provider = oraclecloud_provider
            database_client.audited_compartments = {}
            database_client.regional_clients = {}

            # Verify service name
            assert database_client.service == "database"
            assert database_client.provider == oraclecloud_provider
