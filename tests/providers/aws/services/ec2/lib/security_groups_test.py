import pytest

from prowler.providers.aws.services.ec2.lib.security_groups import _is_cidr_public


class Test_security_groups:
    def test__is_cidr_public_Public_IP(self):
        cidr = "0.0.0.0/0"
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Private_IP(self):
        cidr = "10.0.0.0/8"
        assert not _is_cidr_public(cidr)

    def test__is_cidr_public_Bad_Private_IP(self):
        cidr = "10.0.0.0/0"
        with pytest.raises(ValueError) as ex:
            _is_cidr_public(cidr)

        assert ex.type == ValueError
        assert ex.match(f"{cidr} has host bits set")
