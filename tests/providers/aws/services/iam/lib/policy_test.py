from prowler.providers.aws.services.iam.lib.policy import (
    check_full_service_access,
    is_condition_restricting_from_private_ip,
    is_policy_cross_account,
    is_policy_public,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER


class Test_Policy:
    def test_policy_allows_cross_account_access_with_root_and_wildcard_principal(self):
        policy_allow_root_and_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_cross_account(
            policy_allow_root_and_wildcard_principal, AWS_ACCOUNT_NUMBER
        )

    def test_policy_does_not_allow_cross_account_access_with_specific_root_principal(
        self,
    ):
        policy_allow_specific_root_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_cross_account(
            policy_allow_specific_root_principal, AWS_ACCOUNT_NUMBER
        )

    def test_policy_does_not_allow_cross_account_access_with_deny_effect(self):
        policy_deny_specific_root_principal = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_cross_account(
            policy_deny_specific_root_principal, AWS_ACCOUNT_NUMBER
        )

    def test_policy_allows_public_access_with_wildcard_principal(self):
        policy_allow_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_public(policy_allow_wildcard_principal)

    def test_policy_allows_public_access_with_aws_wildcard_principal(self):
        policy_allow_aws_wildcard_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert is_policy_public(policy_allow_aws_wildcard_principal)

    def test_policy_does_not_allow_public_access_with_specific_aws_principal(self):
        policy_allow_specific_aws_principal = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        assert not is_policy_public(policy_allow_specific_aws_principal)

    def test_policy_does_not_allow_public_access_with_condition(self):
        policy_allow_aws_wildcard_principal_with_condition = {
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
        assert not is_policy_public(policy_allow_aws_wildcard_principal_with_condition)

    def test_policy_allows_full_service_access_with_wildcard_action_and_resource(self):
        policy_allow_wildcard_action_and_resource = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_wildcard_action_and_resource
        )

    def test_policy_does_not_allow_full_service_access_with_specific_get_action(self):
        policy_allow_specific_get_action = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:Get*",
                    "Resource": "*",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_allow_specific_get_action)

    def test_policy_does_not_allow_full_service_access_with_bucket_wildcard_resource(
        self,
    ):
        policy_allow_bucket_wildcard_resource = {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::example_bucket/*",
            }
        }
        assert not check_full_service_access(
            "s3", policy_allow_bucket_wildcard_resource
        )

    def test_policy_does_not_allow_full_service_access_with_specific_bucket(self):
        policy_allow_specific_bucket = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_allow_specific_bucket)

    def test_policy_allows_full_service_access_with_not_action_excluding_other_service(
        self,
    ):
        policy_allow_not_action_excluding_other_service = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "ec2:*",
                    "Resource": "*",
                }
            ]
        }
        assert check_full_service_access(
            "s3", policy_allow_not_action_excluding_other_service
        )

    def test_policy_does_not_allow_full_service_access_with_not_action_including_service(
        self,
    ):
        policy_not_action_including_service = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:*",
                    "Resource": "*",
                }
            ]
        }
        assert not check_full_service_access("s3", policy_not_action_including_service)

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
