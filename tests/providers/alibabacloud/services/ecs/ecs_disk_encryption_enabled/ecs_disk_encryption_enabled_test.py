from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_ecs_disk_encryption_enabled:
    def test_no_disks(self):
        ecs_client = mock.MagicMock
        ecs_client.disks = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled import (
                ecs_disk_encryption_enabled,
            )

            check = ecs_disk_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_disk_encrypted(self):
        ecs_client = mock.MagicMock
        disk_id = "d-test123"
        disk_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:disk/{disk_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled import (
                ecs_disk_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk

            ecs_client.disks = {
                disk_arn: Disk(
                    id=disk_id,
                    name="test-disk",
                    arn=disk_arn,
                    region=ALIBABACLOUD_REGION,
                    disk_type="data",
                    category="cloud_essd",
                    size=100,
                    encrypted=True,
                    kms_key_id="kms-key-123",
                    status="In_use",
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == disk_id
            assert result[0].resource_arn == disk_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "is encrypted" in result[0].status_extended
            assert "kms-key-123" in result[0].status_extended

    def test_disk_not_encrypted(self):
        ecs_client = mock.MagicMock
        disk_id = "d-test456"
        disk_arn = f"acs:ecs:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:disk/{disk_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_disk_encryption_enabled.ecs_disk_encryption_enabled import (
                ecs_disk_encryption_enabled,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Disk

            ecs_client.disks = {
                disk_arn: Disk(
                    id=disk_id,
                    name="unencrypted-disk",
                    arn=disk_arn,
                    region=ALIBABACLOUD_REGION,
                    disk_type="system",
                    category="cloud_ssd",
                    size=50,
                    encrypted=False,
                    status="In_use",
                )
            }
            ecs_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = ecs_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == disk_id
            assert result[0].resource_arn == disk_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "is not encrypted" in result[0].status_extended
