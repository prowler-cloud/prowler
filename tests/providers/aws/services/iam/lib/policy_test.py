from prowler.providers.aws.services.iam.lib.policy import (
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
