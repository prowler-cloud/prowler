from unittest import mock

from prowler.providers.linode.services.instance.instance_service import (
    Instance,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_instance_watchdog_enabled:
    def test_no_instances(self):
        instance_client = mock.MagicMock
        instance_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled import (
                instance_watchdog_enabled,
            )

            check = instance_watchdog_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_instance_watchdog_enabled(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                watchdog_enabled=True,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled import (
                instance_watchdog_enabled,
            )

            check = instance_watchdog_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert "has Watchdog (Lassie) enabled" in result[0].status_extended

    def test_instance_watchdog_disabled(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                watchdog_enabled=False,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_watchdog_enabled.instance_watchdog_enabled import (
                instance_watchdog_enabled,
            )

            check = instance_watchdog_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"
            assert (
                "does not have Watchdog (Lassie) enabled" in result[0].status_extended
            )
