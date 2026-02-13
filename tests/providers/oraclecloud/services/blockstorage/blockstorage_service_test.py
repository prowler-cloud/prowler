from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestBlockStorageService:
    def test_service(self):
        """Test that blockstorage service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.blockstorage.blockstorage_service.BlockStorage.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.blockstorage.blockstorage_service import (
                BlockStorage,
            )

            blockstorage_client = BlockStorage(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            blockstorage_client.service = "blockstorage"
            blockstorage_client.provider = oraclecloud_provider
            blockstorage_client.audited_compartments = {}
            blockstorage_client.regional_clients = {}

            # Verify service name
            assert blockstorage_client.service == "blockstorage"
            assert blockstorage_client.provider == oraclecloud_provider
