from prowler.providers.aws.services.ec2.lib.network_acls import check_network_acl

default_deny_entry_ingress_IPv4 = {
    "CidrBlock": "0.0.0.0/0",
    "Egress": False,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "deny",
    "RuleNumber": 32767,
}

default_deny_entry_ingress_IPv6 = {
    "Ipv6CidrBlock": "::/0",
    "Egress": False,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "deny",
    "RuleNumber": 32768,
}

default_deny_entry_egress_IPv4 = {
    "CidrBlock": "0.0.0.0/0",
    "Egress": True,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "deny",
    "RuleNumber": 32767,
}

default_deny_entry_egress_IPv6 = {
    "Ipv6CidrBlock": "::/0",
    "Egress": True,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "deny",
    "RuleNumber": 32768,
}

allow_all_entry_ingress_IPv4 = {
    "CidrBlock": "0.0.0.0/0",
    "Egress": False,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "allow",
    "RuleNumber": 32766,
}

allow_all_entry_ingress_IPv6 = {
    "Ipv6CidrBlock": "::/0",
    "Egress": False,
    "NetworkAclId": "acl-072d520d07e1c1471",
    "Protocol": "-1",
    "RuleAction": "allow",
    "RuleNumber": 32766,
}


class Test_Network_Acls_IPv4_Only:
    def test_check_IPv4_only_ingress_port_default_entries_deny(self):
        check_port = 22
        any_protocol = "-1"
        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_allow_port(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_deny_port(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_deny_port_in_range(self):
        check_port = 22
        port_from = 21
        port_to = 24
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        assert not check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_deny_port_out_range(self):
        check_port = 22
        port_from = 31
        port_to = 34
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_deny_port_order_incorrect(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 102,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_deny_port_order_correct(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 101,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 102,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_only_ingress_port_with_allow_port_but_egress(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": True,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)


class Test_Network_Acls_IPv4_IPv6:
    def test_check_IPv4_IPv6_ingress_port_default_entries_deny_both(self):
        check_port = 22
        any_protocol = "-1"
        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_IPv4(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_IPV6(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_both(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_IPv4(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_IPv6(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_both(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 100,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 101,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_in_range_IPv4(self):
        check_port = 22
        port_from = 21
        port_to = 24
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_in_range_IPv6(self):
        check_port = 22
        port_from = 21
        port_to = 24
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_in_range_both(self):
        check_port = 22
        port_from = 21
        port_to = 24
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 101,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert not check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_out_range_IPv4(self):
        check_port = 22
        port_from = 31
        port_to = 34
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_out_range_IPv6(self):
        check_port = 22
        port_from = 31
        port_to = 34
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_out_range_both(self):
        check_port = 22
        port_from = 31
        port_to = 34
        tcp_protocol = "6"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 100,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": tcp_protocol,
                "RuleAction": "deny",
                "PortRange": {"From": port_from, "To": port_to},
                "RuleNumber": 101,
            }
        )

        # Allow All IPv4
        entries.append(allow_all_entry_ingress_IPv4)

        # Allow All IPv6
        entries.append(allow_all_entry_ingress_IPv6)

        assert check_network_acl(entries, tcp_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_incorrect_IPv4(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 102,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_incorrect_IPv6(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 102,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_incorrect_both(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 102,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 202,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 201,
            }
        )

        assert check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_correct_IPv4(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 101,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 102,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_correct_IPv6(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 101,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 102,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_deny_port_order_correct_both(self):
        check_port = 22
        any_protocol = "-1"

        entries = []
        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 101,
            }
        )

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 102,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "deny",
                "RuleNumber": 201,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": False,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 202,
            }
        )
        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_but_egress_IPv4(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": True,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_but_egress_IPv6(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": True,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)

    def test_check_IPv4_IPv6_ingress_port_with_allow_port_but_egress_both(self):
        check_port = 22
        any_protocol = "-1"

        entries = []

        # Default IPv4 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv4)

        # Default IPv4 Egress Deny
        entries.append(default_deny_entry_egress_IPv4)

        # Default IPv6 Ingress Deny
        entries.append(default_deny_entry_ingress_IPv6)

        # Default IPv6 Egress Deny
        entries.append(default_deny_entry_egress_IPv6)

        entries.append(
            {
                "Ipv6CidrBlock": "::/0",
                "Egress": True,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 100,
            }
        )

        entries.append(
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": True,
                "NetworkAclId": "acl-072d520d07e1c1471",
                "Protocol": any_protocol,
                "RuleAction": "allow",
                "RuleNumber": 101,
            }
        )

        assert not check_network_acl(entries, any_protocol, check_port)
