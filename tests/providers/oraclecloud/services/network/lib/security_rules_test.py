"""Tests for the Oracle Cloud network security rule helpers."""

import pytest

from prowler.providers.oraclecloud.services.network.lib.security_rules import (
    UNRESTRICTED_CIDRS,
    find_unrestricted_tcp_rule,
    is_public_cidr,
    rule_allows_tcp_port,
)


class Test_is_public_cidr:
    @pytest.mark.parametrize(
        "cidr",
        [
            pytest.param("0.0.0.0/0", id="ipv4-any"),
            pytest.param("::/0", id="ipv6-any"),
            pytest.param("0.0.0.0/0 ", id="ipv4-any-with-trailing-space"),
        ],
    )
    def test_unrestricted_cidrs_are_public(self, cidr):
        assert is_public_cidr(cidr) is True

    @pytest.mark.parametrize(
        "cidr",
        [
            pytest.param("10.0.0.0/8", id="private-ipv4-range"),
            pytest.param("2001:db8::/32", id="private-ipv6-range"),
            pytest.param("1.1.1.1/32", id="public-host-ipv4"),
            pytest.param("", id="empty-string"),
            pytest.param(None, id="none"),
        ],
    )
    def test_other_cidrs_are_not_public(self, cidr):
        assert is_public_cidr(cidr) is False

    def test_unrestricted_cidrs_tuple(self):
        """Both the IPv4 and the IPv6 any-address blocks must be covered."""
        assert UNRESTRICTED_CIDRS == ("0.0.0.0/0", "::/0")


class Test_rule_allows_tcp_port:
    @pytest.mark.parametrize(
        "rule",
        [
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
                },
                id="exact-port",
            ),
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 20, "max": 30}},
                },
                id="port-inside-range",
            ),
            pytest.param(
                {"source": "::/0", "protocol": "6"},
                id="no-tcp-options-means-every-port",
            ),
            pytest.param(
                {"source": "::/0", "protocol": "6", "tcp_options": {}},
                id="empty-tcp-options-means-every-port",
            ),
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"source_port_range": {"min": 1024, "max": 65535}},
                },
                id="only-source-port-range-means-every-destination-port",
            ),
            pytest.param(
                {"source": "::/0", "protocol": "all"},
                id="all-protocols",
            ),
            pytest.param(
                {"source": "::/0"},
                id="no-protocol-means-every-protocol",
            ),
            pytest.param(
                {"source": "::/0", "protocol": None},
                id="null-protocol-means-every-protocol",
            ),
            pytest.param(
                {
                    "source": "10.0.0.0/8",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
                },
                id="source-agnostic-a-restricted-source-still-matches-tcp-22",
            ),
        ],
    )
    def test_rule_allows_port(self, rule):
        assert rule_allows_tcp_port(rule, 22) is True

    @pytest.mark.parametrize(
        "rule",
        [
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 23, "max": 30}},
                },
                id="port-range-above-target",
            ),
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "17",
                    "udp_options": {"destination_port_range": {"min": 22, "max": 22}},
                },
                id="udp-is-not-tcp",
            ),
            pytest.param(
                {"source": "::/0", "protocol": "1", "icmp_options": {"type": 3}},
                id="icmp-has-no-tcp-ports",
            ),
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 20, "max": 21}},
                },
                id="port-range-below-target",
            ),
            pytest.param(
                {
                    "source": "::/0",
                    "protocol": "6",
                    "tcp_options": {"destination_port_range": {"min": 23, "max": 23}},
                },
                id="port-range-above-target",
            ),
        ],
    )
    def test_rule_does_not_allow_port(self, rule):
        assert rule_allows_tcp_port(rule, 22) is False


class Test_find_unrestricted_tcp_rule:
    def test_returns_none_without_rules(self):
        assert find_unrestricted_tcp_rule([], 22) is None
        assert find_unrestricted_tcp_rule(None, 22) is None

    def test_ignores_restricted_sources(self):
        rules = [
            {
                "source": "10.0.0.0/8",
                "protocol": "6",
                "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
            }
        ]
        assert find_unrestricted_tcp_rule(rules, 22) is None

    def test_matches_ipv6_any_source(self):
        rule = {
            "source": "::/0",
            "protocol": "6",
            "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
        }
        assert find_unrestricted_tcp_rule([rule], 22) is rule

    def test_matches_ipv4_any_source(self):
        rule = {
            "source": "0.0.0.0/0",
            "protocol": "6",
            "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
        }
        assert find_unrestricted_tcp_rule([rule], 22) is rule

    def test_direction_filter_skips_egress(self):
        egress_rule = {
            "direction": "EGRESS",
            "source": "0.0.0.0/0",
            "protocol": "6",
            "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
        }
        assert (
            find_unrestricted_tcp_rule([egress_rule], 22, direction="INGRESS") is None
        )
        assert find_unrestricted_tcp_rule([egress_rule], 22) is egress_rule

    def test_direction_filter_matches_ingress(self):
        ingress_rule = {
            "direction": "INGRESS",
            "source": "::/0",
            "protocol": "all",
        }
        assert (
            find_unrestricted_tcp_rule([ingress_rule], 22, direction="INGRESS")
            is ingress_rule
        )

    def test_returns_first_matching_rule(self):
        restricted = {
            "source": "10.0.0.0/8",
            "protocol": "6",
            "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
        }
        public_v4 = {
            "source": "0.0.0.0/0",
            "protocol": "6",
            "tcp_options": {"destination_port_range": {"min": 22, "max": 22}},
        }
        public_v6 = {"source": "::/0", "protocol": "all"}
        assert (
            find_unrestricted_tcp_rule([restricted, public_v4, public_v6], 22)
            is public_v4
        )
