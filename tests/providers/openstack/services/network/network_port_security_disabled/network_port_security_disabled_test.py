"""Tests for network_port_security_disabled check."""

from unittest import mock

from prowler.providers.openstack.services.network.network_service import (
    NetworkResource,
    Port,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class Test_network_port_security_disabled:
    """Test suite for network_port_security_disabled check."""

    def test_no_resources(self):
        """Test when no networks or ports exist."""
        network_client = mock.MagicMock()
        network_client.networks = []
        network_client.ports = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",  # noqa: E501
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled.network_client",  # noqa: E501
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled import (  # noqa: E501
                network_port_security_disabled,
            )

            check = network_port_security_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_network_port_security_enabled(self):
        """Test network with port security enabled (PASS)."""
        network_client = mock.MagicMock()
        network_client.networks = [
            NetworkResource(
                id="net-1",
                name="secure-network",
                status="ACTIVE",
                admin_state_up=True,
                shared=False,
                external=False,
                port_security_enabled=True,
                subnets=["subnet-1"],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                tags=[],
            )
        ]
        network_client.ports = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled import (
                network_port_security_disabled,
            )

            check = network_port_security_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "net-1"
            assert "has port security enabled" in result[0].status_extended

    def test_network_port_security_disabled(self):
        """Test network with port security disabled (FAIL)."""
        network_client = mock.MagicMock()
        network_client.networks = [
            NetworkResource(
                id="net-2",
                name="insecure-network",
                status="ACTIVE",
                admin_state_up=True,
                shared=False,
                external=False,
                port_security_enabled=False,
                subnets=[],
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
                tags=[],
            )
        ]
        network_client.ports = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled import (
                network_port_security_disabled,
            )

            check = network_port_security_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has port security disabled" in result[0].status_extended
            assert "spoofing" in result[0].status_extended

    def test_port_security_disabled(self):
        """Test port with security disabled (FAIL)."""
        network_client = mock.MagicMock()
        network_client.networks = []
        network_client.ports = [
            Port(
                id="port-1",
                name="nfv-port",
                network_id="net-1",
                mac_address="fa:16:3e:00:00:01",
                fixed_ips=[{"ip_address": "192.168.1.10"}],
                port_security_enabled=False,
                security_groups=[],
                device_owner="compute:nova",
                device_id="instance-1",
                project_id=OPENSTACK_PROJECT_ID,
                region=OPENSTACK_REGION,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_openstack_provider(),
            ),
            mock.patch(
                "prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled.network_client",
                new=network_client,
            ),
        ):
            from prowler.providers.openstack.services.network.network_port_security_disabled.network_port_security_disabled import (
                network_port_security_disabled,
            )

            check = network_port_security_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "port-1"
