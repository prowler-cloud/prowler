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
    fw.get_rules.return_value = rules
    return fw


def _build_service(
    networking_firewalls_return=None, networking_firewalls_side_effect=None
):
    """Build a FirewallService instance with a properly isolated mock client."""
    service = object.__new__(FirewallService)
    service.firewalls = []

    # Build an isolated mock hierarchy for client.networking.firewalls()
    # Must explicitly create the firewalls callable as a fresh MagicMock
    # because check tests contaminate MagicMock class with firewalls=[...]
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

    def test_describe_firewalls_handles_rules_fetch_error(self):
        """Firewall is still added even if rules fail to load."""
        fw = MagicMock()
        fw.id = 1
        fw.label = "broken-fw"
        fw.status = "enabled"
        fw.tags = []
        fw.get_rules.side_effect = Exception("rules API error")

        service = _build_service(networking_firewalls_return=[fw])
        service._describe_firewalls()

        assert len(service.firewalls) == 1
        assert service.firewalls[0].label == "broken-fw"
        assert len(service.firewalls[0].inbound_rules) == 0
