from unittest import mock

from prowler.providers.e2enetworks.services.storage.storage_service import (
    BlockVolume,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.storage.storage_block_volume_not_orphaned.storage_block_volume_not_orphaned.storage_client"


class Test_storage_block_volume_not_orphaned:
    def test_no_block_volumes(self):
        client = mock.MagicMock()
        client.block_volumes = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_block_volume_not_orphaned.storage_block_volume_not_orphaned import (
                storage_block_volume_not_orphaned,
            )

            assert storage_block_volume_not_orphaned().execute() == []

    def test_storage_block_volume_not_orphaned_compliant(self):
        client = mock.MagicMock()
        client.block_volumes = [
            BlockVolume(id="1", name="ok", location="Delhi", is_attached=True),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_block_volume_not_orphaned.storage_block_volume_not_orphaned import (
                storage_block_volume_not_orphaned,
            )

            findings = storage_block_volume_not_orphaned().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_storage_block_volume_not_orphaned_non_compliant(self):
        client = mock.MagicMock()
        client.block_volumes = [
            BlockVolume(
                id="2",
                name="bad",
                location="Delhi",
                status="Available",
                is_attached=False,
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.storage.storage_block_volume_not_orphaned.storage_block_volume_not_orphaned import (
                storage_block_volume_not_orphaned,
            )

            findings = storage_block_volume_not_orphaned().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
