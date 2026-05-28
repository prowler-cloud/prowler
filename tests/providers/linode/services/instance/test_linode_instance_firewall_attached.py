from unittest import mock
from unittest.mock import MagicMock, patch

from prowler.providers.linode.services.instance.instance_service import (
    Instance,
)


def mock_provider():
    provider = MagicMock()
    provider.type = "linode"
    return provider


class TestLinodeInstanceFirewallAttached:
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
