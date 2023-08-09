import pytest

from prowler.providers.aws.services.ec2.lib.security_groups import _is_cidr_public


class Test_security_groups:
    def test__is_cidr_public_Public_IPv4_all_IPs_any_address_false(self):
        cidr = "0.0.0.0/0"
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv4__all_IPs_any_address_true(self):
        cidr = "0.0.0.0/0"
        assert _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Public_IPv4_any_address_false(self):
        cidr = "84.28.12.2/32"
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv4_any_address_true(self):
        cidr = "84.28.12.2/32"
        assert not _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Private_IPv4(self):
        cidr = "10.0.0.0/8"
        assert not _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Private_IPv4_any_address_true(self):
        cidr = "10.0.0.0/8"
        assert not _is_cidr_public(cidr)

    def test__is_cidr_public_Bad_Private_IPv4(self):
        cidr = "10.0.0.0/0"
        with pytest.raises(ValueError) as ex:
            _is_cidr_public(cidr)

        assert ex.type == ValueError
        assert ex.match(f"{cidr} has host bits set")

    def test__is_cidr_public_Public_IPv6_all_IPs_any_address_false(self):
        cidr = "::/0"
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv6_all_IPs_any_adress_true(self):
        cidr = "::/0"
        assert _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Public_IPv6(self):
        cidr = "cafe:cafe:cafe:cafe::/64"
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv6_any_adress_true(self):
        cidr = "cafe:cafe:cafe:cafe::/64"
        assert not _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Private_IPv6(self):
        cidr = "fc00::/7"
        assert not _is_cidr_public(cidr)

    def test__is_cidr_public_Private_IPv6_any_adress_true(self):
        cidr = "fc00::/7"
        assert not _is_cidr_public(cidr, any_address=True)
