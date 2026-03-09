from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestEcsUnattachedDiskEncrypted:
    def test_unattached_disk_not_encrypted_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.disks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_unattached_disk_encrypted.ecs_unattached_disk_encrypted.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk
            from prowler.providers.alibabacloud.services.ecs.ecs_unattached_disk_encrypted.ecs_unattached_disk_encrypted import (
                ecs_unattached_disk_encrypted,
            )

            disk = Disk(
                id="d1",
                name="d1",
                region="cn-hangzhou",
                status="Available",
                disk_category="cloud",
                size=20,
                is_attached=False,
                is_encrypted=False,
            )
            ecs_client.disks = [disk]

            check = ecs_unattached_disk_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_unattached_disk_encrypted_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.disks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_unattached_disk_encrypted.ecs_unattached_disk_encrypted.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk
            from prowler.providers.alibabacloud.services.ecs.ecs_unattached_disk_encrypted.ecs_unattached_disk_encrypted import (
                ecs_unattached_disk_encrypted,
            )

            disk = Disk(
                id="d2",
                name="d2",
                region="cn-hangzhou",
                status="Available",
                disk_category="cloud",
                size=20,
                is_attached=False,
                is_encrypted=True,
            )
            ecs_client.disks = [disk]

            check = ecs_unattached_disk_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
