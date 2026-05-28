from unittest import mock

from prowler.providers.linode.services.instance.instance_service import (
    Instance,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_instance_firewall_attached:
    def test_no_instances(self):
        instance_client = mock.MagicMock
        instance_client.instances = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached import (
                instance_firewall_attached,
            )

            check = instance_firewall_attached()
            result = check.execute()

            assert len(result) == 0

    def test_instance_with_public_ip_and_firewall(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                ipv4_public=["192.0.2.1"],
                firewalls_count=1,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached import (
                instance_firewall_attached,
            )

            check = instance_firewall_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "12345"
            assert result[0].resource_name == "my-linode"

    def test_instance_with_public_ip_no_firewall(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="my-linode",
                region="us-east",
                status="running",
                ipv4_public=["192.0.2.1"],
                firewalls_count=0,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached import (
                instance_firewall_attached,
            )

            check = instance_firewall_attached()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "12345"
            assert "192.0.2.1" in result[0].status_extended

    def test_instance_without_public_ip_skipped(self):
        instance_client = mock.MagicMock
        instance_client.instances = [
            Instance(
                id=12345,
                label="private-linode",
                region="us-east",
                status="running",
                ipv4_public=[],
                firewalls_count=0,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached.instance_client",
                new=instance_client,
            ),
        ):
            from prowler.providers.linode.services.instance.instance_firewall_attached.instance_firewall_attached import (
                instance_firewall_attached,
            )

            check = instance_firewall_attached()
            result = check.execute()

            assert len(result) == 0
