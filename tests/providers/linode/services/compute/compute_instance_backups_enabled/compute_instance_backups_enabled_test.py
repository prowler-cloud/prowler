from unittest import mock

from prowler.providers.linode.services.compute.compute_service import (
    Instance,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_compute_instance_backups_enabled:
    def test_no_instances(self):
        compute_client = mock.MagicMock()
        compute_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled import (
                compute_instance_backups_enabled,
            )

            check = compute_instance_backups_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_compute_instance_backups_enabled(self):
        compute_client = mock.MagicMock()
        compute_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                backups_enabled=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled import (
                compute_instance_backups_enabled,
            )

            check = compute_instance_backups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert "has the Backup service enabled" in result[0].status_extended

    def test_instance_backups_disabled(self):
        compute_client = mock.MagicMock()
        compute_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                backups_enabled=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.linode.services.compute.compute_instance_backups_enabled.compute_instance_backups_enabled import (
                compute_instance_backups_enabled,
            )

            check = compute_instance_backups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert (
                "does not have the Backup service enabled" in result[0].status_extended
            )
