from unittest import mock

from prowler.providers.linode.services.instance.instance_service import (
    Instance,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_instance_disk_encryption_enabled:
    def test_no_instances(self):
        instance_client = mock.MagicMock
        instance_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled import (
                instance_disk_encryption_enabled,
            )

            check = instance_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_instance_disk_encryption_enabled(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                disk_encryption="enabled",
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled import (
                instance_disk_encryption_enabled,
            )

            check = instance_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert "has disk encryption enabled" in result[0].status_extended

    def test_instance_disk_encryption_disabled(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                disk_encryption="disabled",
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_disk_encryption_enabled.instance_disk_encryption_enabled import (
                instance_disk_encryption_enabled,
            )

            check = instance_disk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert "does not have disk encryption enabled" in result[0].status_extended
