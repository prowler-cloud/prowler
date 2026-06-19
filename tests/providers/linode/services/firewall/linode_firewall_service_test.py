from unittest.mock import MagicMock

from prowler.providers.linode.services.firewall.firewall_service import (
    FirewallService,
)


def _mock_rule(
    protocol="TCP", ports="22", ipv4=None, ipv6=None, action="ACCEPT", label=""
):
    rule = MagicMock()
    rule.protocol = protocol
    rule.ports = ports
    rule.action = action
    rule.label = label
    addresses = MagicMock()
    addresses.ipv4 = ipv4 or []
    addresses.ipv6 = ipv6 or []
    rule.addresses = addresses
    return rule


def _mock_firewall(
    id=1, label="my-fw", status="enabled", inbound=None, outbound=None, tags=None
):
    fw = MagicMock()
    fw.id = id
    fw.label = label
    fw.status = status
    fw.tags = tags or []
    rules = MagicMock()
    rules.inbound = inbound or []
    rules.outbound = outbound or []
    rules.inbound_policy = "DROP"
    rules.outbound_policy = "DROP"
    fw.rules = rules
    return fw


def _build_service(
    networking_firewalls_return=None, networking_firewalls_side_effect=None
):
    """Build a FirewallService instance with a properly isolated mock client."""
    service = object.__new__(FirewallService)
    service.firewalls = []

    firewalls_callable = MagicMock()
    if networking_firewalls_side_effect:
        firewalls_callable.side_effect = networking_firewalls_side_effect
    else:
        firewalls_callable.return_value = networking_firewalls_return or []

    networking_mock = MagicMock()
    networking_mock.firewalls = firewalls_callable

    client_mock = MagicMock()
    client_mock.networking = networking_mock
    service.client = client_mock
    return service


class TestLinodeFirewallService:
    def test_describe_firewalls_parses_correctly(self):
        inbound_rules = [
            _mock_rule("TCP", "22", ipv4=["192.168.1.0/24"]),
            _mock_rule("TCP", "443", ipv4=["0.0.0.0/0"]),
        ]
        mock_fws = [
            _mock_firewall(id=1, label="prod-fw", inbound=inbound_rules),
        ]

        service = _build_service(networking_firewalls_return=mock_fws)
        service._describe_firewalls()

        assert len(service.firewalls) == 1
        assert service.firewalls[0].label == "prod-fw"
        assert len(service.firewalls[0].inbound_rules) == 2
        assert service.firewalls[0].inbound_rules[0].ports == "22"
        assert service.firewalls[0].inbound_rules[0].addresses_ipv4 == [
            "192.168.1.0/24"
        ]
        assert service.firewalls[0].inbound_rules[1].addresses_ipv4 == ["0.0.0.0/0"]

    def test_describe_firewalls_handles_empty_list(self):
        service = _build_service(networking_firewalls_return=[])
        service._describe_firewalls()

        assert len(service.firewalls) == 0

    def test_describe_firewalls_handles_api_error(self):
        service = _build_service(
            networking_firewalls_side_effect=Exception("API error")
        )
        service._describe_firewalls()

        assert len(service.firewalls) == 0

    def test_describe_firewalls_device_fetch_error_yields_none_count(self):
        """A devices fetch failure must leave attached_devices_count as None
        (undetermined) rather than 0, to avoid a false 'not assigned' FAIL."""

        class _NoDevicesFw:
            id = 5
            label = "no-devices-fw"
            status = "enabled"
            tags = []

            @property
            def devices(self):
                raise Exception("devices API error")

            @property
            def rules(self):
                r = MagicMock()
                r.inbound = []
                r.outbound = []
                r.inbound_policy = "DROP"
                r.outbound_policy = "DROP"
                return r

        service = _build_service(networking_firewalls_return=[_NoDevicesFw()])
        service._describe_firewalls()

        assert len(service.firewalls) == 1
        assert service.firewalls[0].attached_devices_count is None

    def test_describe_firewalls_handles_null_rule_fields(self):
        """Rule fields returned as explicit null must fall back to defaults
        instead of raising a ValidationError that drops the whole firewall."""
        rule = MagicMock()
        rule.protocol = None
        rule.ports = None
        rule.action = None
        rule.label = None
        addresses = MagicMock()
        addresses.ipv4 = None
        addresses.ipv6 = None
        rule.addresses = addresses

        mock_fws = [_mock_firewall(id=6, label="null-rule-fw", inbound=[rule])]

        service = _build_service(networking_firewalls_return=mock_fws)
        service._describe_firewalls()

        assert len(service.firewalls) == 1
        parsed = service.firewalls[0].inbound_rules[0]
        assert parsed.protocol == "TCP"
        assert parsed.action == "ACCEPT"
        assert parsed.ports == ""
        assert parsed.addresses_ipv4 == []
        assert parsed.addresses_ipv6 == []
        assert parsed.label == ""

    def test_describe_firewalls_handles_rules_fetch_error(self):
        """Firewall is still added even if rules fail to load."""

        class _BrokenFw:
            id = 1
            label = "broken-fw"
            status = "enabled"
            tags = []
            devices = []

            @property
            def rules(self):
                raise Exception("rules API error")

        fw = _BrokenFw()

        service = _build_service(networking_firewalls_return=[fw])
        service._describe_firewalls()

        assert len(service.firewalls) == 1
        assert service.firewalls[0].label == "broken-fw"
        assert len(service.firewalls[0].inbound_rules) == 0
