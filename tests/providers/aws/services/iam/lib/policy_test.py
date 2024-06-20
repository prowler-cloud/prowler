from prowler.providers.aws.services.iam.lib.policy import (
    check_full_service_access,
    has_private_conditions,
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

    def test_check_full_service_access(self):
        policy1 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ]
        }
        policy2 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:Get*",
                    "Resource": "*",
                }
            ]
        }
        policy3 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket/*",
                }
            ]
        }
        policy4 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::example_bucket",
                }
            ]
        }

        assert check_full_service_access("s3", policy1)
        assert not check_full_service_access("s3", policy2)
        assert not check_full_service_access("s3", policy3)
        assert not check_full_service_access("s3", policy4)

    def test_statemetns_with_private_conditions(self):
        statement_no_conditions = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
        }
        statement_condition_from_vpc = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-123456"}},
        }
        statement_condition_public_IP = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4"}},
        }
        statement_condition_private_IP = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": "192.168.4.234"}},
        }

        assert not has_private_conditions(statement_no_conditions)
        assert has_private_conditions(statement_condition_from_vpc)
        assert not has_private_conditions(statement_condition_public_IP)
        assert has_private_conditions(statement_condition_private_IP)
