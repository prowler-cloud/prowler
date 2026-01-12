from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestEcsAttachedDiskEncrypted:
    def test_attached_disk_not_encrypted_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.disks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_attached_disk_encrypted.ecs_attached_disk_encrypted.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_attached_disk_encrypted.ecs_attached_disk_encrypted import (
                ecs_attached_disk_encrypted,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk

            disk = Disk(
                id="d1",
                name="d1",
                region="cn-hangzhou",
                status="In-use",
                disk_category="cloud",
                size=20,
                is_attached=True,
                attached_instance_id="i-1",
                is_encrypted=False,
            )
            ecs_client.disks = [disk]

            check = ecs_attached_disk_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_attached_disk_encrypted_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.disks = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_attached_disk_encrypted.ecs_attached_disk_encrypted.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_attached_disk_encrypted.ecs_attached_disk_encrypted import (
                ecs_attached_disk_encrypted,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk

            disk = Disk(
                id="d2",
                name="d2",
                region="cn-hangzhou",
                status="In-use",
                disk_category="cloud",
                size=20,
                is_attached=True,
                attached_instance_id="i-2",
                is_encrypted=True,
            )
            ecs_client.disks = [disk]

            check = ecs_attached_disk_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
