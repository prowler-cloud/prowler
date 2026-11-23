import pytest

from prowler.providers.alibabacloud.services.ecs.lib.security_groups import (
    format_ports,
    get_publicly_exposed_tcp_ports,
    is_public_ingress_exposing_all_ports,
    port_in_range,
)


@pytest.mark.parametrize(
    "port_range,target_port,expected",
    [
        ("22", 22, True),
        ("22/22", 22, True),
        ("20/22", 20, True),
        ("20/22", 22, True),
        ("20/22", 23, False),
        ("-1/-1", 22, False),
        ("0/65535", 0, True),
        ("0/65535", 65535, True),
        ("22/20", 21, False),
        ("", 22, False),
        ("invalid", 22, False),
        ("20/22/23", 22, False),
        ("-1/22", 22, False),
        ("0/65536", 22, False),
        ("22", -1, False),
        ("22", 65536, False),
    ],
)
def test_port_in_range(port_range, target_port, expected):
    assert port_in_range(port_range, target_port) is expected


@pytest.mark.parametrize(
    "rule,target_ports,expected",
    [
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "22/22",
            },
            [22],
            True,
        ),
        (
            {
                "policy": "aCcEpT",
                "ip_protocol": "TCP",
                "ipv_6source_cidr_ip": "::/0",
                "port_range": "20/23",
            },
            [22],
            True,
        ),
        (
            {
                "policy": "DROP",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "22/22",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "udp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "22/22",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "20/23",
            },
            [22],
            True,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "ALL",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "80/443",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "-1/-1",
            },
            [22, 3389],
            True,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "10.0.0.0/8",
                "port_range": "22/22",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "203.0.113.0/24",
                "port_range": "22/22",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "1433/1434",
            },
            [3306, 1434],
            True,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "1433/1434",
            },
            [3306, 5432],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "1434/1433",
            },
            [1433],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "",
            },
            [22],
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "not-a-range",
            },
            [22],
            False,
        ),
    ],
)
def test_is_public_ingress_rule_exposing_tcp_ports(rule, target_ports, expected):
    assert bool(get_publicly_exposed_tcp_ports([rule], target_ports)) is expected


@pytest.mark.parametrize(
    "rule,expected",
    [
        (
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "-1/-1",
            },
            True,
        ),
        (
            {
                "policy": "ACCEPT",
                "ip_protocol": "ALL",
                "ipv_6source_cidr_ip": "::/0",
                "port_range": "-1/-1",
            },
            True,
        ),
        (
            {
                "policy": "Drop",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "-1/-1",
            },
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "tcp",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "-1/-1",
            },
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "0.0.0.0/0",
                "port_range": "22/22",
            },
            False,
        ),
        (
            {
                "policy": "Accept",
                "ip_protocol": "all",
                "source_cidr_ip": "10.0.0.0/8",
                "port_range": "-1/-1",
            },
            False,
        ),
    ],
)
def test_is_public_ingress_rule_exposing_all_ports(rule, expected):
    assert is_public_ingress_exposing_all_ports([rule]) is expected


def test_lower_priority_number_wins_and_drop_wins_ties():
    rules = [
        {
            "policy": "Accept",
            "priority": 2,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
        {
            "policy": "Drop",
            "priority": 1,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
        {
            "policy": "Accept",
            "priority": 5,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "23/23",
        },
        {
            "policy": "Drop",
            "priority": 5,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "23/23",
        },
    ]

    assert get_publicly_exposed_tcp_ports(rules, [22, 23]) == set()


def test_accept_in_either_address_family_is_exposed():
    rules = [
        {
            "policy": "Drop",
            "priority": 1,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "tcp",
            "ipv_6source_cidr_ip": "::/0",
            "port_range": "22/22",
        },
    ]

    assert get_publicly_exposed_tcp_ports(rules, [22]) == {22}


def test_missing_priority_defaults_to_one_but_malformed_priority_is_ignored():
    rules = [
        {
            "policy": "Accept",
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
        {
            "policy": "Accept",
            "priority": "invalid",
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "23/23",
        },
    ]

    assert get_publicly_exposed_tcp_ports(rules, [22, 23]) == {22}


def test_tcp_wildcard_does_not_expose_target_ports():
    rule = {
        "policy": "Accept",
        "priority": 1,
        "ip_protocol": "tcp",
        "source_cidr_ip": "0.0.0.0/0",
        "port_range": "-1/-1",
    }

    assert get_publicly_exposed_tcp_ports([rule], [22]) == set()


@pytest.mark.parametrize(
    "protocol,port_range",
    [
        ("all", "-1/-1"),
        ("all", "0/65535"),
        ("all", "1/65535"),
    ],
)
def test_full_ranges_expose_all_ports(protocol, port_range):
    rule = {
        "policy": "Accept",
        "priority": 2,
        "ip_protocol": protocol,
        "source_cidr_ip": "0.0.0.0/0",
        "port_range": port_range,
    }

    assert is_public_ingress_exposing_all_ports([rule]) is True


@pytest.mark.parametrize("port_range", ["0/65535", "1/65535"])
def test_tcp_full_ranges_do_not_expose_all_protocols(port_range):
    rule = {
        "policy": "Accept",
        "priority": 1,
        "ip_protocol": "tcp",
        "source_cidr_ip": "0.0.0.0/0",
        "port_range": port_range,
    }

    assert is_public_ingress_exposing_all_ports([rule]) is False


def test_bounded_protocol_all_union_exposes_all_ports():
    rules = [
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "all",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "1/32767",
        },
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "all",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "32768/65535",
        },
    ]

    assert is_public_ingress_exposing_all_ports(rules) is True


def test_bounded_tcp_union_does_not_expose_all_protocols():
    rules = [
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "1/32767",
        },
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "32768/65535",
        },
    ]

    assert is_public_ingress_exposing_all_ports(rules) is False


def test_higher_priority_partial_drop_prevents_all_port_exposure():
    rules = [
        {
            "policy": "Accept",
            "priority": 2,
            "ip_protocol": "all",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "-1/-1",
        },
        {
            "policy": "Drop",
            "priority": 1,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
    ]

    assert is_public_ingress_exposing_all_ports(rules) is False


def test_lower_priority_partial_drop_does_not_prevent_all_port_exposure():
    rules = [
        {
            "policy": "Accept",
            "priority": 1,
            "ip_protocol": "all",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "1/65535",
        },
        {
            "policy": "Drop",
            "priority": 2,
            "ip_protocol": "tcp",
            "source_cidr_ip": "0.0.0.0/0",
            "port_range": "22/22",
        },
    ]

    assert is_public_ingress_exposing_all_ports(rules) is True


@pytest.mark.parametrize(
    "ports,expected",
    [
        ([], ""),
        ((3389,), "3389"),
        ({22, 3389}, "22 and 3389"),
        ([22, 80, 443], "22, 80, and 443"),
    ],
)
def test_format_ports(ports, expected):
    assert format_ports(ports) == expected
