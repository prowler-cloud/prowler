from prowler.providers.aws.services.iam.lib.policy import (
    is_condition_restricting_from_private_ip,
    is_policy_cross_account,
    is_policy_public,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER


class Test_Policy:
    def test_is_policy_cross_account(self):
        policy1 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy2 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy3 = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }

        assert is_policy_cross_account(policy1, AWS_ACCOUNT_NUMBER)
        assert not is_policy_cross_account(policy2, AWS_ACCOUNT_NUMBER)
        assert not is_policy_cross_account(policy3, AWS_ACCOUNT_NUMBER)

    def test_is_policy_public(self):
        policy1 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy2 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy3 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy4 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}},
                }
            ]
        }

        assert is_policy_public(policy1)
        assert is_policy_public(policy2)
        assert not is_policy_public(policy3)
        assert not is_policy_public(policy4)

    def test_is_condition_restricting_from_private_ip_no_condition(self):
        assert not is_condition_restricting_from_private_ip({})

    def test_is_condition_restricting_from_private_ip(self):
        condition_from_private_ip = {
            "IpAddress": {"aws:SourceIp": "10.0.0.22"},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ip)

    def test_is_condition_restricting_from_public_ip(self):
        condition_not_from_private_ip = {
            "IpAddress": {"aws:SourceIp": "1.2.3.4"},
        }
        assert not is_condition_restricting_from_private_ip(
            condition_not_from_private_ip
        )

    def test_is_condition_restricting_from_private_ipv6(self):
        condition_from_private_ipv6 = {
            "IpAddress": {"aws:SourceIp": "fd00::1"},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ipv6)

    def test_is_condition_restricting_from_public_ipv6(self):
        condition_not_from_private_ipv6 = {
            "IpAddress": {"aws:SourceIp": "2001:0db8::1"},
        }
        assert is_condition_restricting_from_private_ip(condition_not_from_private_ipv6)

    def test_is_condition_restricting_from_private_ip_network(self):
        condition_from_private_ip_network = {
            "IpAddress": {"aws:SourceIp": "10.0.0.0/24"},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ip_network
        )

    def test_is_condition_restricting_from_public_ip_network(self):
        condition_from_public_ip_network = {
            "IpAddress": {"aws:SourceIp": "1.2.3.0/24"},
        }

        assert not is_condition_restricting_from_private_ip(
            condition_from_public_ip_network
        )

    def test_is_condition_restricting_from_private_ipv6_network(self):
        condition_from_private_ipv6_network = {
            "IpAddress": {"aws:SourceIp": "fd00::/8"},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ipv6_network
        )

    def test_is_condition_restricting_from_private_ip_array(self):
        condition_from_private_ip_array = {
            "IpAddress": {"aws:SourceIp": ["10.0.0.22", "192.168.1.1"]},
        }
        assert is_condition_restricting_from_private_ip(condition_from_private_ip_array)

    def test_is_condition_restricting_from_private_ipv6_array(self):
        condition_from_private_ipv6_array = {
            "IpAddress": {"aws:SourceIp": ["fd00::1", "fe80::1"]},
        }
        assert is_condition_restricting_from_private_ip(
            condition_from_private_ipv6_array
        )

    def test_is_condition_restricting_from_mixed_ip_array(self):
        condition_from_mixed_ip_array = {
            "IpAddress": {"aws:SourceIp": ["10.0.0.22", "2001:0db8::1"]},
        }
        assert is_condition_restricting_from_private_ip(condition_from_mixed_ip_array)

    def test_is_condition_restricting_from_mixed_ip_array_not_private(self):
        condition_from_mixed_ip_array_not_private = {
            "IpAddress": {"aws:SourceIp": ["1.2.3.4", "2001:0db8::1"]},
        }
        assert not is_condition_restricting_from_private_ip(
            condition_from_mixed_ip_array_not_private
        )

    def test_is_condition_restricting_from_private_ip_from_invalid_ip(self):
        condition_from_invalid_ip = {
            "IpAddress": {"aws:SourceIp": "256.256.256.256"},
        }
        assert not is_condition_restricting_from_private_ip(condition_from_invalid_ip)
