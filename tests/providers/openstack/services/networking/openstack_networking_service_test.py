"""Tests for OpenStack Network service."""

from unittest.mock import MagicMock, patch

from openstack import exceptions as openstack_exceptions

from prowler.providers.openstack.services.networking.networking_service import (
    Networking,
    NetworkResource,
    Port,
    SecurityGroup,
    SecurityGroupRule,
    Subnet,
)
from tests.providers.openstack.openstack_fixtures import (
    OPENSTACK_PROJECT_ID,
    OPENSTACK_REGION,
    set_mocked_openstack_provider,
)


class TestNetworkingService:
    """Test suite for Network service."""

    def test_network_service_initialization(self):
        """Test Network service initializes correctly."""
        provider = set_mocked_openstack_provider()

        with (
            patch.object(Networking, "_list_security_groups", return_value=[]),
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert network.service_name == "Networking"
            assert network.provider == provider
            assert network.connection == provider.connection
            assert network.regional_connections == provider.regional_connections
            assert network.audited_regions == [OPENSTACK_REGION]
            assert network.region == OPENSTACK_REGION
            assert network.project_id == OPENSTACK_PROJECT_ID
            assert network.security_groups == []
            assert network.networks == []
            assert network.subnets == []
            assert network.ports == []

    def test_network_list_security_groups_success(self):
        """Test listing security groups successfully."""
        provider = set_mocked_openstack_provider()

        # Mock security group rule
        mock_rule = MagicMock()
        mock_rule.id = "rule-1"
        mock_rule.security_group_id = "sg-1"
        mock_rule.direction = "ingress"
        mock_rule.protocol = "tcp"
        mock_rule.ethertype = "IPv4"
        mock_rule.port_range_min = 22
        mock_rule.port_range_max = 22
        mock_rule.remote_ip_prefix = "0.0.0.0/0"
        mock_rule.remote_group_id = None

        # Mock security group
        mock_sg = MagicMock()
        mock_sg.id = "sg-1"
        mock_sg.name = "web-servers"
        mock_sg.description = "Security group for web servers"
        mock_sg.security_group_rules = [mock_rule]
        mock_sg.project_id = OPENSTACK_PROJECT_ID
        mock_sg.tags = ["production"]

        provider.connection.network.security_groups.return_value = [mock_sg]

        with (
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert len(network.security_groups) == 1
            assert isinstance(network.security_groups[0], SecurityGroup)
            assert network.security_groups[0].id == "sg-1"
            assert network.security_groups[0].name == "web-servers"
            assert network.security_groups[0].is_default is False
            assert len(network.security_groups[0].security_group_rules) == 1

            rule = network.security_groups[0].security_group_rules[0]
            assert isinstance(rule, SecurityGroupRule)
            assert rule.id == "rule-1"
            assert rule.direction == "ingress"
            assert rule.protocol == "tcp"
            assert rule.port_range_min == 22
            assert rule.port_range_max == 22
            assert rule.remote_ip_prefix == "0.0.0.0/0"

    def test_network_list_security_groups_default(self):
        """Test listing default security group."""
        provider = set_mocked_openstack_provider()

        mock_sg = MagicMock()
        mock_sg.id = "sg-default"
        mock_sg.name = "default"
        mock_sg.description = "Default security group"
        mock_sg.security_group_rules = []
        mock_sg.project_id = OPENSTACK_PROJECT_ID
        mock_sg.tags = []

        provider.connection.network.security_groups.return_value = [mock_sg]

        with (
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert len(network.security_groups) == 1
            assert network.security_groups[0].name == "default"
            assert network.security_groups[0].is_default is True

    def test_network_list_security_groups_empty(self):
        """Test listing security groups when none exist."""
        provider = set_mocked_openstack_provider()
        provider.connection.network.security_groups.return_value = []

        with (
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert network.security_groups == []

    def test_network_list_security_groups_sdk_exception(self):
        """Test handling SDKException when listing security groups."""
        provider = set_mocked_openstack_provider()
        provider.connection.network.security_groups.side_effect = (
            openstack_exceptions.SDKException("API error")
        )

        with (
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert network.security_groups == []

    def test_network_list_networks_success(self):
        """Test listing networks successfully."""
        provider = set_mocked_openstack_provider()

        mock_net = MagicMock()
        mock_net.id = "net-1"
        mock_net.name = "private-network"
        mock_net.status = "ACTIVE"
        mock_net.is_admin_state_up = True
        mock_net.is_shared = False
        mock_net.is_router_external = False
        mock_net.is_port_security_enabled = True
        mock_net.subnet_ids = ["subnet-1", "subnet-2"]
        mock_net.project_id = OPENSTACK_PROJECT_ID
        mock_net.tags = []

        provider.connection.network.networks.return_value = [mock_net]

        with (
            patch.object(Networking, "_list_security_groups", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert len(network.networks) == 1
            assert isinstance(network.networks[0], NetworkResource)
            assert network.networks[0].id == "net-1"
            assert network.networks[0].name == "private-network"
            assert network.networks[0].port_security_enabled is True

    def test_network_list_subnets_success(self):
        """Test listing subnets successfully."""
        provider = set_mocked_openstack_provider()

        mock_subnet = MagicMock()
        mock_subnet.id = "subnet-1"
        mock_subnet.name = "private-subnet"
        mock_subnet.network_id = "net-1"
        mock_subnet.ip_version = 4
        mock_subnet.cidr = "192.168.1.0/24"
        mock_subnet.gateway_ip = "192.168.1.1"
        mock_subnet.is_dhcp_enabled = True
        mock_subnet.dns_nameservers = ["8.8.8.8", "8.8.4.4"]
        mock_subnet.project_id = OPENSTACK_PROJECT_ID

        provider.connection.network.subnets.return_value = [mock_subnet]

        with (
            patch.object(Networking, "_list_security_groups", return_value=[]),
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_ports", return_value=[]),
        ):
            network = Networking(provider)

            assert len(network.subnets) == 1
            assert isinstance(network.subnets[0], Subnet)
            assert network.subnets[0].id == "subnet-1"
            assert network.subnets[0].cidr == "192.168.1.0/24"

    def test_network_list_ports_success(self):
        """Test listing ports successfully."""
        provider = set_mocked_openstack_provider()

        mock_port = MagicMock()
        mock_port.id = "port-1"
        mock_port.name = "instance-port"
        mock_port.network_id = "net-1"
        mock_port.mac_address = "fa:16:3e:00:00:01"
        mock_port.fixed_ips = [{"ip_address": "192.168.1.10", "subnet_id": "subnet-1"}]
        mock_port.is_port_security_enabled = True
        mock_port.security_groups = ["sg-1"]
        mock_port.device_owner = "compute:nova"
        mock_port.device_id = "instance-1"
        mock_port.project_id = OPENSTACK_PROJECT_ID

        provider.connection.network.ports.return_value = [mock_port]

        with (
            patch.object(Networking, "_list_security_groups", return_value=[]),
            patch.object(Networking, "_list_networks", return_value=[]),
            patch.object(Networking, "_list_subnets", return_value=[]),
        ):
            network = Networking(provider)

            assert len(network.ports) == 1
            assert isinstance(network.ports[0], Port)
            assert network.ports[0].id == "port-1"
            assert network.ports[0].port_security_enabled is True
            assert network.ports[0].security_groups == ["sg-1"]

    def test_network_dataclasses_attributes(self):
        """Test dataclass attributes are correctly set."""
        rule = SecurityGroupRule(
            id="rule-1",
            security_group_id="sg-1",
            direction="ingress",
            protocol="tcp",
            ethertype="IPv4",
            port_range_min=80,
            port_range_max=80,
            remote_ip_prefix="0.0.0.0/0",
            remote_group_id=None,
        )

        assert rule.id == "rule-1"
        assert rule.protocol == "tcp"
        assert rule.port_range_min == 80

        sg = SecurityGroup(
            id="sg-1",
            name="web",
            description="Web servers",
            security_group_rules=[rule],
            project_id="project-1",
            region="RegionOne",
            is_default=False,
            tags=["prod"],
        )

        assert sg.id == "sg-1"
        assert len(sg.security_group_rules) == 1
        assert sg.is_default is False

    def test_networking_list_security_groups_multi_region(self):
        """Test listing security groups across multiple regions."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_sg_uk = MagicMock()
        mock_sg_uk.id = "sg-uk"
        mock_sg_uk.name = "web-uk"
        mock_sg_uk.description = "UK web servers"
        mock_sg_uk.security_group_rules = []
        mock_sg_uk.project_id = OPENSTACK_PROJECT_ID
        mock_sg_uk.tags = []

        mock_sg_de = MagicMock()
        mock_sg_de.id = "sg-de"
        mock_sg_de.name = "web-de"
        mock_sg_de.description = "DE web servers"
        mock_sg_de.security_group_rules = []
        mock_sg_de.project_id = OPENSTACK_PROJECT_ID
        mock_sg_de.tags = []

        mock_conn_uk1.network.security_groups.return_value = [mock_sg_uk]
        mock_conn_de1.network.security_groups.return_value = [mock_sg_de]
        mock_conn_uk1.network.networks.return_value = []
        mock_conn_de1.network.networks.return_value = []
        mock_conn_uk1.network.subnets.return_value = []
        mock_conn_de1.network.subnets.return_value = []
        mock_conn_uk1.network.ports.return_value = []
        mock_conn_de1.network.ports.return_value = []

        network = Networking(provider)

        assert len(network.security_groups) == 2
        uk_sg = next(sg for sg in network.security_groups if sg.id == "sg-uk")
        de_sg = next(sg for sg in network.security_groups if sg.id == "sg-de")
        assert uk_sg.region == "UK1"
        assert de_sg.region == "DE1"

    def test_networking_list_networks_multi_region(self):
        """Test listing networks across multiple regions."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_net_uk = MagicMock()
        mock_net_uk.id = "net-uk"
        mock_net_uk.name = "private-uk"
        mock_net_uk.status = "ACTIVE"
        mock_net_uk.is_admin_state_up = True
        mock_net_uk.is_shared = False
        mock_net_uk.is_router_external = False
        mock_net_uk.is_port_security_enabled = True
        mock_net_uk.subnet_ids = ["subnet-uk"]
        mock_net_uk.project_id = OPENSTACK_PROJECT_ID
        mock_net_uk.tags = []

        mock_net_de = MagicMock()
        mock_net_de.id = "net-de"
        mock_net_de.name = "private-de"
        mock_net_de.status = "ACTIVE"
        mock_net_de.is_admin_state_up = True
        mock_net_de.is_shared = False
        mock_net_de.is_router_external = False
        mock_net_de.is_port_security_enabled = True
        mock_net_de.subnet_ids = ["subnet-de"]
        mock_net_de.project_id = OPENSTACK_PROJECT_ID
        mock_net_de.tags = []

        mock_conn_uk1.network.security_groups.return_value = []
        mock_conn_de1.network.security_groups.return_value = []
        mock_conn_uk1.network.networks.return_value = [mock_net_uk]
        mock_conn_de1.network.networks.return_value = [mock_net_de]
        mock_conn_uk1.network.subnets.return_value = []
        mock_conn_de1.network.subnets.return_value = []
        mock_conn_uk1.network.ports.return_value = []
        mock_conn_de1.network.ports.return_value = []

        network = Networking(provider)

        assert len(network.networks) == 2
        uk_net = next(n for n in network.networks if n.id == "net-uk")
        de_net = next(n for n in network.networks if n.id == "net-de")
        assert uk_net.region == "UK1"
        assert de_net.region == "DE1"

    def test_networking_list_subnets_multi_region(self):
        """Test listing subnets across multiple regions."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_subnet_uk = MagicMock()
        mock_subnet_uk.id = "subnet-uk"
        mock_subnet_uk.name = "subnet-uk"
        mock_subnet_uk.network_id = "net-uk"
        mock_subnet_uk.ip_version = 4
        mock_subnet_uk.cidr = "10.0.0.0/24"
        mock_subnet_uk.gateway_ip = "10.0.0.1"
        mock_subnet_uk.is_dhcp_enabled = True
        mock_subnet_uk.dns_nameservers = ["8.8.8.8"]
        mock_subnet_uk.project_id = OPENSTACK_PROJECT_ID

        mock_subnet_de = MagicMock()
        mock_subnet_de.id = "subnet-de"
        mock_subnet_de.name = "subnet-de"
        mock_subnet_de.network_id = "net-de"
        mock_subnet_de.ip_version = 4
        mock_subnet_de.cidr = "10.1.0.0/24"
        mock_subnet_de.gateway_ip = "10.1.0.1"
        mock_subnet_de.is_dhcp_enabled = True
        mock_subnet_de.dns_nameservers = ["8.8.4.4"]
        mock_subnet_de.project_id = OPENSTACK_PROJECT_ID

        mock_conn_uk1.network.security_groups.return_value = []
        mock_conn_de1.network.security_groups.return_value = []
        mock_conn_uk1.network.networks.return_value = []
        mock_conn_de1.network.networks.return_value = []
        mock_conn_uk1.network.subnets.return_value = [mock_subnet_uk]
        mock_conn_de1.network.subnets.return_value = [mock_subnet_de]
        mock_conn_uk1.network.ports.return_value = []
        mock_conn_de1.network.ports.return_value = []

        network = Networking(provider)

        assert len(network.subnets) == 2
        uk_subnet = next(s for s in network.subnets if s.id == "subnet-uk")
        de_subnet = next(s for s in network.subnets if s.id == "subnet-de")
        assert uk_subnet.region == "UK1"
        assert de_subnet.region == "DE1"

    def test_networking_list_ports_multi_region(self):
        """Test listing ports across multiple regions."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_port_uk = MagicMock()
        mock_port_uk.id = "port-uk"
        mock_port_uk.name = "port-uk"
        mock_port_uk.network_id = "net-uk"
        mock_port_uk.mac_address = "fa:16:3e:00:00:01"
        mock_port_uk.fixed_ips = [{"ip_address": "10.0.0.10", "subnet_id": "subnet-uk"}]
        mock_port_uk.is_port_security_enabled = True
        mock_port_uk.security_groups = ["sg-uk"]
        mock_port_uk.device_owner = "compute:nova"
        mock_port_uk.device_id = "instance-uk"
        mock_port_uk.project_id = OPENSTACK_PROJECT_ID

        mock_port_de = MagicMock()
        mock_port_de.id = "port-de"
        mock_port_de.name = "port-de"
        mock_port_de.network_id = "net-de"
        mock_port_de.mac_address = "fa:16:3e:00:00:02"
        mock_port_de.fixed_ips = [{"ip_address": "10.1.0.10", "subnet_id": "subnet-de"}]
        mock_port_de.is_port_security_enabled = True
        mock_port_de.security_groups = ["sg-de"]
        mock_port_de.device_owner = "compute:nova"
        mock_port_de.device_id = "instance-de"
        mock_port_de.project_id = OPENSTACK_PROJECT_ID

        mock_conn_uk1.network.security_groups.return_value = []
        mock_conn_de1.network.security_groups.return_value = []
        mock_conn_uk1.network.networks.return_value = []
        mock_conn_de1.network.networks.return_value = []
        mock_conn_uk1.network.subnets.return_value = []
        mock_conn_de1.network.subnets.return_value = []
        mock_conn_uk1.network.ports.return_value = [mock_port_uk]
        mock_conn_de1.network.ports.return_value = [mock_port_de]

        network = Networking(provider)

        assert len(network.ports) == 2
        uk_port = next(p for p in network.ports if p.id == "port-uk")
        de_port = next(p for p in network.ports if p.id == "port-de")
        assert uk_port.region == "UK1"
        assert de_port.region == "DE1"

    def test_networking_multi_region_partial_failure(self):
        """Test that a failing region doesn't prevent other regions from being listed."""
        provider = set_mocked_openstack_provider()

        mock_conn_ok = MagicMock()
        mock_conn_fail = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_ok, "DE1": mock_conn_fail}

        mock_sg = MagicMock()
        mock_sg.id = "sg-uk"
        mock_sg.name = "web-uk"
        mock_sg.description = "UK web servers"
        mock_sg.security_group_rules = []
        mock_sg.project_id = OPENSTACK_PROJECT_ID
        mock_sg.tags = []

        mock_conn_ok.network.security_groups.return_value = [mock_sg]
        mock_conn_fail.network.security_groups.side_effect = (
            openstack_exceptions.SDKException("API error in DE1")
        )
        mock_conn_ok.network.networks.return_value = []
        mock_conn_fail.network.networks.side_effect = openstack_exceptions.SDKException(
            "API error in DE1"
        )
        mock_conn_ok.network.subnets.return_value = []
        mock_conn_fail.network.subnets.side_effect = openstack_exceptions.SDKException(
            "API error in DE1"
        )
        mock_conn_ok.network.ports.return_value = []
        mock_conn_fail.network.ports.side_effect = openstack_exceptions.SDKException(
            "API error in DE1"
        )

        network = Networking(provider)

        assert len(network.security_groups) == 1
        assert network.security_groups[0].id == "sg-uk"
        assert network.security_groups[0].region == "UK1"

    def test_networking_multi_region_one_empty(self):
        """Test multi-region where one region has resources and the other is empty."""
        provider = set_mocked_openstack_provider()

        mock_conn_uk1 = MagicMock()
        mock_conn_de1 = MagicMock()

        provider.regional_connections = {"UK1": mock_conn_uk1, "DE1": mock_conn_de1}

        mock_net = MagicMock()
        mock_net.id = "net-uk"
        mock_net.name = "private-uk"
        mock_net.status = "ACTIVE"
        mock_net.is_admin_state_up = True
        mock_net.is_shared = False
        mock_net.is_router_external = False
        mock_net.is_port_security_enabled = True
        mock_net.subnet_ids = []
        mock_net.project_id = OPENSTACK_PROJECT_ID
        mock_net.tags = []

        mock_conn_uk1.network.security_groups.return_value = []
        mock_conn_de1.network.security_groups.return_value = []
        mock_conn_uk1.network.networks.return_value = [mock_net]
        mock_conn_de1.network.networks.return_value = []
        mock_conn_uk1.network.subnets.return_value = []
        mock_conn_de1.network.subnets.return_value = []
        mock_conn_uk1.network.ports.return_value = []
        mock_conn_de1.network.ports.return_value = []

        network = Networking(provider)

        assert len(network.networks) == 1
        assert network.networks[0].id == "net-uk"
        assert network.networks[0].region == "UK1"
