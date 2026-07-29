from unittest.mock import MagicMock, patch

from prowler.providers.e2enetworks.services.storage.storage_service import Storage


class TestStorageService:
    @patch(
        "prowler.providers.e2enetworks.services.storage.storage_service.E2eNetworksService.__init__"
    )
    def test_fetch_efs_and_epfs(self, mock_super_init):
        mock_super_init.return_value = None

        provider = MagicMock()
        provider.session.locations = ["Delhi"]
        service = Storage.__new__(Storage)
        service.provider = provider
        service.client = MagicMock()
        service.block_volumes = []
        service.efs_volumes = []
        service.epfs_volumes = []

        service.client.paginate.return_value = [
            {
                "id": 1396,
                "name": "sfs-993",
                "status": "Available",
                "vpc_id": 6882,
                "is_backup_enabled": True,
                "is_all_vpc_resources_allowed": False,
            }
        ]
        service.client.get.return_value = {
            "data": [
                {
                    "id": 145,
                    "name": "epfs-1",
                    "deleted": False,
                    "vpc": {"network_id": 34872, "name": "VPC-717"},
                }
            ],
            "total_page_number": 1,
        }

        service._fetch_efs_volumes()
        service._fetch_epfs_volumes()

        assert len(service.efs_volumes) == 1
        assert service.efs_volumes[0].is_backup_enabled is True
        assert len(service.epfs_volumes) == 1
        assert service.epfs_volumes[0].vpc_network_id == "34872"
