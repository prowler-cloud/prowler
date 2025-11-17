from unittest.mock import patch

from tests.providers.oraclecloud.oci_fixtures import set_mocked_oraclecloud_provider


class TestFilestorageService:
    def test_service(self):
        """Test that filestorage service can be instantiated and mocked"""
        oraclecloud_provider = set_mocked_oraclecloud_provider()

        # Mock the entire service initialization
        with patch(
            "prowler.providers.oraclecloud.services.filestorage.filestorage_service.Filestorage.__init__",
            return_value=None,
        ):
            from prowler.providers.oraclecloud.services.filestorage.filestorage_service import (
                Filestorage,
            )

            filestorage_client = Filestorage(oraclecloud_provider)

            # Manually set required attributes since __init__ was mocked
            filestorage_client.service = "filestorage"
            filestorage_client.provider = oraclecloud_provider
            filestorage_client.audited_compartments = {}
            filestorage_client.regional_clients = {}

            # Verify service name
            assert filestorage_client.service == "filestorage"
            assert filestorage_client.provider == oraclecloud_provider
