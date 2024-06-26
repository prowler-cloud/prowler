import pytest

from prowler.providers.aws.services.ec2.lib.security_groups import (
    _is_cidr_public,
    check_security_group,
)

TRANSPORT_PROTOCOL_TCP = "tcp"
TRANSPORT_PROTOCOL_ALL = "-1"

IP_V4_ALL_CIDRS = "0.0.0.0/0"
IP_V4_PUBLIC_CIDR = "84.28.12.2/32"
IP_V4_PRIVATE_CIDR = "10.1.0.0/16"

IP_V6_ALL_CIDRS = "::/0"
IP_V6_PUBLIC_CIDR = "cafe:cafe:cafe:cafe::/64"
IP_V6_PRIVATE_CIDR = "fc00::/7"


class Test_is_cidr_public:
    def test__is_cidr_public_Public_IPv4_all_IPs_any_address_false(self):
        cidr = IP_V4_ALL_CIDRS
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv4__all_IPs_any_address_true(self):
        cidr = IP_V4_ALL_CIDRS
        assert _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Public_IPv4_any_address_false(self):
        cidr = IP_V4_PUBLIC_CIDR
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv4_any_address_true(self):
        cidr = IP_V4_PUBLIC_CIDR
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
        cidr = IP_V6_ALL_CIDRS
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv6_all_IPs_any_adress_true(self):
        cidr = IP_V6_ALL_CIDRS
        assert _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Public_IPv6(self):
        cidr = IP_V6_PUBLIC_CIDR
        assert _is_cidr_public(cidr)

    def test__is_cidr_public_Public_IPv6_any_adress_true(self):
        cidr = IP_V6_PUBLIC_CIDR
        assert not _is_cidr_public(cidr, any_address=True)

    def test__is_cidr_public_Private_IPv6(self):
        cidr = IP_V6_PRIVATE_CIDR
        assert not _is_cidr_public(cidr)

    def test__is_cidr_public_Private_IPv6_any_adress_true(self):
        cidr = IP_V6_PRIVATE_CIDR
        assert not _is_cidr_public(cidr, any_address=True)


class Test_check_security_group:
    def generate_ip_ranges_list(self, input_ip_ranges: [str], v4=True):
        cidr_ranges = "CidrIp" if v4 else "CidrIpv6"
        return [{cidr_ranges: ip, "Description": ""} for ip in input_ip_ranges]

    def ingress_rule_generator(
        self,
        from_port: int,
        to_port: int,
        ip_protocol: str,
        input_ipv4_ranges: [str],
        input_ipv6_ranges: [str],
    ):
        """
        ingress_rule_generator returns the following AWS Security Group IpPermissions Ingress Rule based on the input arguments
        {
            'FromPort': 123,
            'IpProtocol': 'string',
            'IpRanges': [
                {
                    'CidrIp': 'string',
                    'Description': 'string'
                },
            ],
            'Ipv6Ranges': [
                {
                    'CidrIpv6': 'string',
                    'Description': 'string'
                },
            ],
            'ToPort': 123,
        }
        """
        ipv4_ranges = self.generate_ip_ranges_list(input_ipv4_ranges)
        ipv6_ranges = self.generate_ip_ranges_list(input_ipv6_ranges, v4=False)

        ingress_rule = {
            "FromPort": from_port,
            "ToPort": to_port,
            "IpProtocol": ip_protocol,
            "IpRanges": ipv4_ranges,
            "Ipv6Ranges": ipv6_ranges,
        }
        return ingress_rule

    # TCP Protocol - IP_V4_ALL_CIDRS - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_all_public_ipv4_address_open_22_tcp_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_v4_PUBLIC_CIDR - Ingress 22 to 22 - check 22 - Open
    def test_public_ipv4_address_open_22_tcp(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PUBLIC_CIDR], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False)

    # TCP Protocol - IP_v4_PUBLIC_CIDR - Ingress 22 to 22 - check 22 - Any Address - Closed
    def test_public_ipv4_address_open_22_tcp_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PUBLIC_CIDR], []
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True
        )

    # TCP Protocol - IP_V4_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Any Address - Closed
    def test_private_ipv4_address_open_22_tcp_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PRIVATE_CIDR], []
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False
        )

    # TCP Protocol - IP_V4_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Closed
    def test_private_ipv4_address_open_22_tcp(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PRIVATE_CIDR], []
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False
        )

    # TCP Protocol - IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_all_public_ipv6_address_open_22_tcp_any_address(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Open
    def test_all_public_ipv6_address_open_22_tcp(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False)

    # TCP Protocol - IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Open
    def test_public_ipv6_address_open_22_tcp(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_PUBLIC_CIDR]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False)

    # TCP Protocol - IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Any Address - Closed
    def test_public_ipv6_address_open_22_tcp_any_address(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_PUBLIC_CIDR]
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True
        )

    # TCP Protocol - IP_V6_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Any Address - Closed
    def test_all_private_ipv6_address_open_22_tcp_any_address(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_PRIVATE_CIDR]
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True
        )

    # TCP Protocol - IP_V6_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Closed
    def test_all_private_ipv6_address_open_22_tcp(self):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_PRIVATE_CIDR]
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True
        )

    # TCP Protocol - IP_V4_PRIVATE_CIDR + IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_private_ipv4_all_public_ipv6_address_open_22_tcp_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PRIVATE_CIDR], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_V4_PRIVATE_CIDR + IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Open
    def test_private_ipv4_all_public_ipv6_address_open_22_tcp(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_PRIVATE_CIDR], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_V4_ALL_CIDRS + IP_V6_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_all_public_ipv4_private_ipv6_address_open_22_tcp_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_ALL_CIDRS], [IP_V6_PRIVATE_CIDR]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_V4_ALL_CIDRS + IP_V6_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Open
    def test_all_public_ipv4_private_ipv6_address_open_22_tcp(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_TCP, [IP_V4_ALL_CIDRS], [IP_V6_PRIVATE_CIDR]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], False)

    # ALL (-1) Protocol - IP_V4_ALL_CIDRS - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_all_public_ipv4_address_open_22_any_protocol_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # ALL (-1) Protocol - IP_V4_PUBLIC_CIDR - Ingress 22 to 22 - check 22 - Closed
    def test_all_public_ipv4_address_open_22_any_protocol(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [IP_V4_PUBLIC_CIDR], []
        )
        assert not check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True
        )

    # ALL (-1) Protocol - IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Open
    def test_all_public_ipv6_address_open_22_any_protocol_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # ALL (-1) Protocol - IP_V4_PRIVATE_CIDR + IP_V6_ALL_CIDRS - Ingress 22 to 22 - check 22 - Open
    def test_private_ipv4_all_public_ipv6_address_open_22_any_protocol_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [IP_V4_PRIVATE_CIDR], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # ALL (-1) Protocol - IP_V4_ALL_CIDRS + IP_V6_PRIVATE_CIDR - Ingress 22 to 22 - check 22 - Any Address - Open
    def test_all_public_ipv4_private_ipv6_address_open_22_any_protocol_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [IP_V4_ALL_CIDRS], [IP_V6_PRIVATE_CIDR]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [port], True)

    # TCP Protocol - IP_V4_ALL_CIDRS - Ingress 21 to 23 - check 22 - Any Address - Any Address - Open
    def test_all_public_ipv4_address_open_21_to_23_check_22_tcp_any_address(
        self,
    ):
        ingress_rule = self.ingress_rule_generator(
            21, 23, TRANSPORT_PROTOCOL_TCP, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_TCP, [22], True)

    # TCP Protocol - IP_V4_ALL_CIDRS - All Ports - check None - Any Address - Open
    def test_all_public_ipv4_address_open_all_ports_check_all_tcp_any_address(
        self,
    ):
        ingress_rule = self.ingress_rule_generator(
            0, 65535, TRANSPORT_PROTOCOL_TCP, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, any_address=True
        )

    # TCP Protocol - IP_V6_ALL_CIDRS - All Ports - check None - Any Address - Open
    def test_all_public_ipv6_address_open_all_ports_check_all_tcp_any_address(
        self,
    ):
        ingress_rule = self.ingress_rule_generator(
            0, 65535, TRANSPORT_PROTOCOL_TCP, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(
            ingress_rule, TRANSPORT_PROTOCOL_TCP, any_address=True
        )

    # ALL (-1) Protocol - IP_V4_ALL_CIDRS - Any Port - check None - Any Address - Open
    def test_all_public_ipv4_address_open_any_port_check_none_any_address(
        self,
    ):
        ingress_rule = self.ingress_rule_generator(
            0, 65535, TRANSPORT_PROTOCOL_ALL, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_ALL, None, True)

    # ALL (-1) Protocol - IP_V6_ALL_CIDRS - Any Port - check None - Any Address - Open
    def test_all_public_ipv6_address_open_any_port_check_none_any_address(
        self,
    ):
        ingress_rule = self.ingress_rule_generator(
            0, 65535, TRANSPORT_PROTOCOL_ALL, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_ALL, None, True)

    # ALL (-1) Protocol - IP_V4_ALL_CIDRS - Any Port - check None - Any Address - Open
    def test_all_public_ipv4_address_open_22_port_check_none_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [IP_V4_ALL_CIDRS], []
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_ALL, None, True)

    # ALL (-1) Protocol - IP_V6_ALL_CIDRS - Any Port - check None - Any Address - Open
    def test_all_public_ipv6_address_open_22_port_check_none_any_address(
        self,
    ):
        port = 22
        ingress_rule = self.ingress_rule_generator(
            port, port, TRANSPORT_PROTOCOL_ALL, [], [IP_V6_ALL_CIDRS]
        )
        assert check_security_group(ingress_rule, TRANSPORT_PROTOCOL_ALL, None, True)
