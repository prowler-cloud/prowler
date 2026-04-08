"""Tests for the shared is_public_ip utility."""

from prowler.providers.openstack.services.compute.lib.ip import is_public_ip


class Test_is_public_ip:
    def test_public_ipv4(self):
        assert is_public_ip("8.8.8.8")

    def test_public_ipv4_other(self):
        assert is_public_ip("1.1.1.1")

    def test_private_ipv4_10(self):
        assert not is_public_ip("10.0.0.5")

    def test_private_ipv4_172(self):
        assert not is_public_ip("172.16.0.1")

    def test_private_ipv4_192(self):
        assert not is_public_ip("192.168.1.1")

    def test_loopback_ipv4(self):
        assert not is_public_ip("127.0.0.1")

    def test_link_local_ipv4(self):
        assert not is_public_ip("169.254.0.1")

    def test_multicast_ipv4(self):
        assert not is_public_ip("224.0.0.1")

    def test_documentation_ipv4_not_global(self):
        assert not is_public_ip("203.0.113.10")

    def test_public_ipv6(self):
        assert is_public_ip("2001:41d0:801:1000::164b")

    def test_private_ipv6(self):
        assert not is_public_ip("fd00::1")

    def test_loopback_ipv6(self):
        assert not is_public_ip("::1")

    def test_link_local_ipv6(self):
        assert not is_public_ip("fe80::1")

    def test_documentation_ipv6_not_global(self):
        assert not is_public_ip("2001:db8::1")

    def test_invalid_ip(self):
        assert not is_public_ip("not-an-ip")

    def test_empty_string(self):
        assert not is_public_ip("")
