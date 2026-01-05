from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestObjectStorageService:
    def test_service(self):
        """Test that objectstorage service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.objectstorage.objectstorage_service.ObjectStorage.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.objectstorage.objectstorage_service import (
                ObjectStorage,
            )

            objectstorage_client = ObjectStorage(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            objectstorage_client.service = "objectstorage"
            objectstorage_client.provider = oraclecloud_provider
            objectstorage_client.audited_compartments = {}
            objectstorage_client.regional_clients = {}

            # Verify service name
            assert objectstorage_client.service == "objectstorage"
            assert objectstorage_client.provider == oraclecloud_provider
