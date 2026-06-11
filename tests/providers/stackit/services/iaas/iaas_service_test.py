from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from prowler.providers.stackit.exceptions.exceptions import StackITInvalidTokenError
from prowler.providers.stackit.services.iaas.iaas_service import (
    IaaSService,
    SecurityGroupRule,
)
from tests.providers.stackit.stackit_fixtures import (
    STACKIT_PROJECT_ID,
    set_mocked_stackit_provider,
)


def mock_iaas_fetch_all_regions(_):
    """Mock the _fetch_all_regions method to avoid real API calls."""


@patch(
    "prowler.providers.stackit.services.iaas.iaas_service.IaaSService._fetch_all_regions",
    new=mock_iaas_fetch_all_regions,
)
class Test_IaaS_Service:
    def test_service_initialization(self):
        """Test that the IaaS service initializes correctly."""
        iaas_service = IaaSService(set_mocked_stackit_provider())

        assert iaas_service.project_id == STACKIT_PROJECT_ID
        assert iaas_service.service_account_key_path is not None
        assert isinstance(iaas_service.security_groups, list)
        assert isinstance(iaas_service.server_nics, list)
        assert isinstance(iaas_service.in_use_sg_ids, set)
        assert iaas_service.scan_unused_services is False
        assert isinstance(iaas_service.servers, list)
        assert isinstance(iaas_service._nic_device_index, dict)
        assert isinstance(iaas_service._public_ip_server_ids, set)

    def test_service_project_id(self):
        """Test that the service correctly extracts project_id from provider."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert iaas_service.project_id == STACKIT_PROJECT_ID

    def test_service_service_account_key_path(self):
        """Test that the service correctly extracts the SA key path from provider."""
        custom_path = "/tmp/custom-sa.json"
        provider = set_mocked_stackit_provider(service_account_key_path=custom_path)
        iaas_service = IaaSService(provider)
        assert iaas_service.service_account_key_path == custom_path

    def test_security_groups_list_structure(self):
        """Test that security_groups is properly initialized as a list."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "security_groups")
        assert isinstance(iaas_service.security_groups, list)

    def test_in_use_sg_ids_set_structure(self):
        """Test that in_use_sg_ids is properly initialized as a set."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        assert hasattr(iaas_service, "in_use_sg_ids")
        assert isinstance(iaas_service.in_use_sg_ids, set)

    @pytest.mark.parametrize(
        "method_name,client_method_name",
        [
            ("_list_server_nics", "list_project_nics"),
            ("_list_security_groups", "list_security_groups"),
            ("_list_security_group_rules", "list_security_group_rules"),
            ("_list_public_ips", "list_public_ips"),
            ("_list_servers", "list_servers"),
        ],
    )
    def test_list_methods_propagate_api_errors(self, method_name, client_method_name):
        """API/auth failures must fail the scan instead of returning empty data."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        getattr(client, client_method_name).side_effect = StackITInvalidTokenError(
            message="Invalid token"
        )

        with pytest.raises(StackITInvalidTokenError):
            if method_name == "_list_security_group_rules":
                getattr(iaas_service, method_name)(client, "eu01", "sg-1")
            else:
                getattr(iaas_service, method_name)(client, "eu01")

    def test_security_group_parsing_errors_are_skipped_locally(self):
        """Malformed resources are skipped while valid resources are retained."""

        class MalformedSecurityGroup:
            @property
            def id(self):
                raise ValueError("malformed security group")

        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        client.list_security_groups.return_value = [
            MalformedSecurityGroup(),
            {"id": "sg-1", "name": "valid-sg"},
        ]
        client.list_security_group_rules.return_value = []

        iaas_service._list_security_groups(client, "eu01")

        assert len(iaas_service.security_groups) == 1
        assert iaas_service.security_groups[0].id == "sg-1"

    def test_in_use_considers_all_nics_not_only_public(self):
        """A SG attached to any NIC (public or private) counts as in_use."""
        iaas_service = IaaSService(set_mocked_stackit_provider())

        # NIC without a public IP, but has a security group attached
        private_nic = {"id": "nic-private", "security_groups": ["sg-private"]}
        used = iaas_service._get_used_security_group_ids([private_nic])

        assert "sg-private" in used

    def test_in_use_sg_ids_populated_via_list_server_nics(self):
        """_list_server_nics marks SGs on any NIC as in_use."""
        iaas_service = IaaSService(set_mocked_stackit_provider())
        client = MagicMock()
        client.list_project_nics.return_value = [
            {"id": "nic-1", "security_groups": ["sg-1"]},
            {"id": "nic-2", "security_groups": ["sg-2"]},
        ]

        iaas_service._list_server_nics(client, "eu01")

        assert "sg-1" in iaas_service.in_use_sg_ids
        assert "sg-2" in iaas_service.in_use_sg_ids


# Test SecurityGroupRule helper methods
class Test_SecurityGroupRule:
    def test_is_unrestricted_with_none(self):
        """Test that None ip_range is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range=None,
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_unrestricted_with_cidr(self):
        """Test that 0.0.0.0/0 is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_unrestricted_with_ipv6(self):
        """Test that ::/0 is considered unrestricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="::/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is True

    def test_is_restricted_with_specific_ip(self):
        """Test that specific IP range is considered restricted."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="10.0.0.0/8",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_unrestricted() is False

    def test_is_ingress_true(self):
        """Test that ingress direction is properly detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_ingress() is True

    def test_is_ingress_false(self):
        """Test that egress direction returns false for is_ingress."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="egress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_ingress() is False

    def test_is_tcp_with_tcp_protocol(self):
        """Test that TCP protocol is detected correctly."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_none_protocol(self):
        """Test that None protocol is treated as TCP (all protocols)."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol=None,
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_all_protocol(self):
        """Test that 'all' protocol is treated as TCP."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="all",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is True

    def test_is_tcp_with_udp_protocol(self):
        """Test that UDP protocol returns false for is_tcp."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="udp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.is_tcp() is False

    def test_includes_port_exact_match(self):
        """Test that exact port match is detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=22,
            port_range_max=22,
        )
        assert rule.includes_port(22) is True

    def test_includes_port_in_range(self):
        """Test that port within range is detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=20,
            port_range_max=25,
        )
        assert rule.includes_port(22) is True
        assert rule.includes_port(20) is True
        assert rule.includes_port(25) is True

    def test_includes_port_outside_range(self):
        """Test that port outside range is not detected."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=80,
            port_range_max=443,
        )
        assert rule.includes_port(22) is False

    def test_includes_port_with_none_range(self):
        """Test that None port range means all ports."""
        rule = SecurityGroupRule(
            id="rule-1",
            direction="ingress",
            protocol="tcp",
            ip_range="0.0.0.0/0",
            port_range_min=None,
            port_range_max=None,
        )
        assert rule.includes_port(22) is True
        assert rule.includes_port(443) is True
        assert rule.includes_port(65535) is True


class Test_IaaS_Service_Extract_Items:
    """Cover ``IaaSService._extract_items`` against the three response shapes the
    StackIT SDK can return. The previous implementation matched ``dict`` via
    ``hasattr(response, "items")`` and returned the bound method instead of the
    items field.
    """

    def test_extract_items_from_sdk_model(self):
        """SDK models expose ``items`` as a non-callable attribute."""
        response = MagicMock(spec=["items"])
        sentinel = [{"id": "sg-1"}, {"id": "sg-2"}]
        response.items = sentinel
        assert IaaSService._extract_items(response, "endpoint") is sentinel

    def test_extract_items_from_dict_with_items_key(self):
        """Dict responses must use the ``items`` key, not ``dict.items()``."""
        response = {"items": [{"id": "sg-1"}]}
        assert IaaSService._extract_items(response, "endpoint") == [{"id": "sg-1"}]

    def test_extract_items_from_empty_dict(self):
        """An empty dict yields an empty list, not the ``dict.items`` method."""
        assert IaaSService._extract_items({}, "endpoint") == []

    def test_extract_items_from_list(self):
        """A plain list response is returned as-is."""
        response = [{"id": "sg-1"}]
        assert IaaSService._extract_items(response, "endpoint") is response

    def test_extract_items_unknown_shape_returns_empty(self):
        """Unknown shapes fall back to an empty list and log a warning."""
        assert IaaSService._extract_items(42, "endpoint") == []

    def test_extract_items_ignores_dict_items_method(self):
        """Regression: ``dict`` exposes ``items`` as a method; ensure the
        ``isinstance(dict)`` branch wins and we do not return the bound method.
        """
        result = IaaSService._extract_items({"items": ["ok"]}, "endpoint")
        assert result == ["ok"]
        assert not callable(result)


class Test_IaaS_Service_Used_Security_Group_Ids:
    """Cover ``_get_used_security_group_ids``. The SDK returns NIC security
    group references as ``uuid.UUID`` while a security group id is a ``str``;
    they must be normalized to ``str`` so the in-use membership test matches.
    """

    def _service(self):
        return object.__new__(IaaSService)

    def test_uuid_references_are_normalized_to_str(self):
        from uuid import UUID

        sg_uuid = UUID("2040c1fa-72a6-47bc-a53b-f62075ae6d35")
        nic = MagicMock(spec=["security_groups"])
        nic.security_groups = [sg_uuid]

        used = self._service()._get_used_security_group_ids([nic])

        # Stored as the string form so `str(sg.id) in used` matches.
        assert used == {"2040c1fa-72a6-47bc-a53b-f62075ae6d35"}
        assert all(isinstance(x, str) for x in used)

    def test_dict_nic_camelcase_security_groups_key(self):
        nic = {"securityGroups": ["sg-aaaa", "sg-bbbb"]}
        used = self._service()._get_used_security_group_ids([nic])
        assert used == {"sg-aaaa", "sg-bbbb"}

    def test_empty_nic_security_groups(self):
        nic = MagicMock(spec=["security_groups"])
        nic.security_groups = []
        assert self._service()._get_used_security_group_ids([nic]) == set()

    def test_in_use_matches_uuid_reference_end_to_end(self):
        """A security group whose id (str) matches a NIC reference (UUID) must
        be flagged in_use=True after a full region fetch.
        """
        from uuid import UUID

        sg_id = "2040c1fa-72a6-47bc-a53b-f62075ae6d35"
        client = MagicMock()
        nic = MagicMock(spec=["security_groups"])
        nic.security_groups = [UUID(sg_id)]
        client.list_project_nics.return_value = {"items": [nic]}
        client.list_security_groups.return_value = {"items": [{"id": sg_id}]}
        client.list_security_group_rules.return_value = {"items": []}

        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.scan_unused_services = False
        service.regional_clients = {"eu01": client}
        service.security_groups = []
        service.server_nics = []
        service.in_use_sg_ids = set()

        service._fetch_all_regions()

        assert len(service.security_groups) == 1
        assert service.security_groups[0].in_use is True


class Test_IaaS_Service_Fetch_All_Regions:
    """Cover ``_fetch_all_regions`` multi-region behaviour. A project is not
    provisioned in every StackIT region; the region where it is absent answers
    with HTTP 404. That must be skipped, not abort the whole scan (which
    previously left every check failing to load with an empty report).
    """

    class _NotFound(Exception):
        status = 404

    class _Forbidden(Exception):
        status = 403

    def _service(self, regional_clients):
        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        # Reuse the real centralized error handler so 401/403/404 semantics
        # match production.
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.scan_unused_services = True
        service.regional_clients = regional_clients
        service.security_groups = []
        service.server_nics = []
        service.in_use_sg_ids = set()
        service.servers = []
        service._nic_device_index = {}
        service._public_ip_server_ids = set()
        return service

    def _good_client(self, sg_id="sg-eu01"):
        client = MagicMock()
        client.list_project_nics.return_value = {"items": []}
        client.list_security_groups.return_value = {"items": [{"id": sg_id}]}
        client.list_security_group_rules.return_value = {"items": []}
        client.list_public_ips.return_value = {"items": []}
        client.list_servers.return_value = {"items": []}
        return client

    def _missing_region_client(self):
        client = MagicMock()
        client.list_project_nics.side_effect = self._NotFound()
        client.list_security_groups.side_effect = self._NotFound()
        return client

    def test_skips_region_where_project_is_absent(self):
        service = self._service(
            {"eu01": self._good_client(), "eu02": self._missing_region_client()}
        )

        service._fetch_all_regions()

        # eu01 security group is collected; the eu02 404 is skipped silently.
        assert [sg.id for sg in service.security_groups] == ["sg-eu01"]

    def test_403_still_aborts(self):
        bad = MagicMock()
        bad.list_project_nics.side_effect = self._Forbidden()
        service = self._service({"eu01": bad})

        with pytest.raises(StackITInvalidTokenError):
            service._fetch_all_regions()


class Test_IaaS_Service_Log_Skipped_Security_Groups:
    """``_log_skipped_security_groups`` should emit a hint only when groups
    exist, none are in use, and ``scan_unused_services`` is off.
    """

    def _service(self, security_groups, scan_unused_services):
        service = object.__new__(IaaSService)
        service.scan_unused_services = scan_unused_services
        service.security_groups = security_groups
        return service

    def _sg(self, in_use):
        sg = MagicMock()
        sg.in_use = in_use
        return sg

    def test_logs_when_all_skipped(self, caplog):
        import logging

        service = self._service([self._sg(False), self._sg(False)], False)
        with caplog.at_level(logging.INFO):
            service._log_skipped_security_groups()
        assert "scan-unused-services" in caplog.text

    def test_no_log_when_scan_unused_services_enabled(self, caplog):
        import logging

        service = self._service([self._sg(False)], True)
        with caplog.at_level(logging.INFO):
            service._log_skipped_security_groups()
        assert "scan-unused-services" not in caplog.text

    def test_no_log_when_a_group_is_in_use(self, caplog):
        import logging

        service = self._service([self._sg(False), self._sg(True)], False)
        with caplog.at_level(logging.INFO):
            service._log_skipped_security_groups()
        assert "scan-unused-services" not in caplog.text

    def test_no_log_when_no_security_groups(self, caplog):
        import logging

        service = self._service([], False)
        with caplog.at_level(logging.INFO):
            service._log_skipped_security_groups()
        assert "scan-unused-services" not in caplog.text


class Test_IaaS_Service_NIC_Device_Index:
    """NIC device index is built during _list_server_nics to enable
    public IP → server cross-reference.
    """

    def _service(self):
        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.server_nics = []
        service.in_use_sg_ids = set()
        service._nic_device_index = {}
        return service

    def test_nic_with_id_and_device_is_indexed(self):
        service = self._service()
        nic_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        device_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        nic = MagicMock()
        nic.id = nic_id
        nic.device = device_id
        nic.security_groups = []
        client = MagicMock()
        client.list_project_nics.return_value = {"items": [nic]}

        service._list_server_nics(client, "eu01")

        assert str(nic_id) in service._nic_device_index
        assert service._nic_device_index[str(nic_id)] == str(device_id)

    def test_nic_without_device_is_not_indexed(self):
        service = self._service()
        nic = MagicMock()
        nic.id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        nic.device = None
        nic.security_groups = []
        client = MagicMock()
        client.list_project_nics.return_value = {"items": [nic]}

        service._list_server_nics(client, "eu01")

        assert service._nic_device_index == {}


class Test_IaaS_Service_PublicIps:
    """Tests for _list_public_ips."""

    def _service(self):
        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service._nic_device_index = {}
        service._public_ip_server_ids = set()
        return service

    def test_unattached_ip_is_ignored(self):
        service = self._service()
        ip = MagicMock()
        ip.network_interface = None
        client = MagicMock()
        client.list_public_ips.return_value = {"items": [ip]}

        service._list_public_ips(client, "eu01")

        assert service._public_ip_server_ids == set()

    def test_attached_ip_with_known_nic_marks_server(self):
        nic_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        server_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        service = self._service()
        service._nic_device_index = {str(nic_id): server_id}
        ip = MagicMock()
        ip.network_interface = nic_id
        client = MagicMock()
        client.list_public_ips.return_value = {"items": [ip]}

        service._list_public_ips(client, "eu01")

        assert server_id in service._public_ip_server_ids

    def test_attached_ip_with_unknown_nic_is_ignored(self):
        service = self._service()
        service._nic_device_index = {}
        ip = MagicMock()
        ip.network_interface = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        client = MagicMock()
        client.list_public_ips.return_value = {"items": [ip]}

        service._list_public_ips(client, "eu01")

        assert service._public_ip_server_ids == set()


class Test_IaaS_Service_Servers:
    """Tests for _list_servers."""

    def _service(self):
        from prowler.providers.stackit.stackit_provider import StackitProvider

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.servers = []
        service._public_ip_server_ids = set()
        return service

    def test_server_without_public_ip(self):
        server_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        service = self._service()
        server_data = MagicMock()
        server_data.id = server_id
        server_data.name = "my-server"
        client = MagicMock()
        client.list_servers.return_value = {"items": [server_data]}

        service._list_servers(client, "eu01")

        assert len(service.servers) == 1
        assert service.servers[0].has_public_ip is False

    def test_server_with_public_ip(self):
        server_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        service = self._service()
        service._public_ip_server_ids = {str(server_id)}
        server_data = MagicMock()
        server_data.id = server_id
        server_data.name = "my-server"
        client = MagicMock()
        client.list_servers.return_value = {"items": [server_data]}

        service._list_servers(client, "eu01")

        assert len(service.servers) == 1
        assert service.servers[0].has_public_ip is True

    def test_empty_response(self):
        service = self._service()
        client = MagicMock()
        client.list_servers.return_value = {"items": []}

        service._list_servers(client, "eu01")

        assert service.servers == []

    def test_server_public_ip_detected_end_to_end(self):
        """Full cross-reference: NIC → public IP → server flagged has_public_ip."""
        from prowler.providers.stackit.stackit_provider import StackitProvider

        nic_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
        server_id = UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")

        nic = MagicMock()
        nic.id = nic_id
        nic.device = server_id
        nic.security_groups = []

        ip = MagicMock()
        ip.network_interface = nic_id

        server_data = MagicMock()
        server_data.id = server_id
        server_data.name = "internet-server"

        client = MagicMock()
        client.list_project_nics.return_value = {"items": [nic]}
        client.list_security_groups.return_value = {"items": []}
        client.list_public_ips.return_value = {"items": [ip]}
        client.list_servers.return_value = {"items": [server_data]}

        service = object.__new__(IaaSService)
        service.provider = MagicMock()
        service.provider.handle_api_error = StackitProvider.handle_api_error
        service.project_id = STACKIT_PROJECT_ID
        service.scan_unused_services = False
        service.regional_clients = {"eu01": client}
        service.security_groups = []
        service.server_nics = []
        service.in_use_sg_ids = set()
        service.servers = []
        service._nic_device_index = {}
        service._public_ip_server_ids = set()

        service._fetch_all_regions()

        assert len(service.servers) == 1
        assert service.servers[0].has_public_ip is True
