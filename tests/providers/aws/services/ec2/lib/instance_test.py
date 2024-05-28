from unittest.mock import Mock

from prowler.providers.aws.services.ec2.lib.instance import get_instance_public_status


class TestGetInstancePublicStatus:

    def test_instance_no_public_ip(self):
        vpc_subnets = {"subnet-1": Mock(public=False)}
        instance = Mock(id="i-1234567890abcdef0", public_ip=None, subnet_id="subnet-1")
        service = "SSH"

        expected_status = "Instance i-1234567890abcdef0 has SSH exposed to 0.0.0.0/0 but with no public IP address."
        expected_severity = "medium"

        status, severity = get_instance_public_status(vpc_subnets, instance, service)

        assert status == expected_status
        assert severity == expected_severity

    def test_instance_with_public_ip_private_subnet(self):
        vpc_subnets = {"subnet-1": Mock(public=False)}
        instance = Mock(
            id="i-1234567890abcdef0", public_ip="203.0.113.42", subnet_id="subnet-1"
        )
        service = "SSH"

        expected_status = "Instance i-1234567890abcdef0 has SSH exposed to 0.0.0.0/0 on public IP address 203.0.113.42 but it is placed in a private subnet subnet-1."
        expected_severity = "high"

        status, severity = get_instance_public_status(vpc_subnets, instance, service)

        assert status == expected_status
        assert severity == expected_severity

    def test_instance_with_public_ip_public_subnet(self):
        vpc_subnets = {"subnet-1": Mock(public=True)}
        instance = Mock(
            id="i-1234567890abcdef0", public_ip="203.0.113.42", subnet_id="subnet-1"
        )
        service = "SSH"

        expected_status = "Instance i-1234567890abcdef0 has SSH exposed to 0.0.0.0/0 on public IP address 203.0.113.42 in public subnet subnet-1."
        expected_severity = "critical"

        status, severity = get_instance_public_status(vpc_subnets, instance, service)

        assert status == expected_status
        assert severity == expected_severity
