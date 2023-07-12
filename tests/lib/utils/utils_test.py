from prowler.lib.utils.utils import validate_ip_address


class Test_Validate_Ip_Address:
    def test_validate_ip_address(self):
        assert validate_ip_address("88.26.151.198")
        assert not validate_ip_address("Not an IP")
