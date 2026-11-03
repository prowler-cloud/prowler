import json
from unittest import mock

import pytest
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_secure_transport_policy:
    @mock_aws
    def test_bucket_no_policy(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have a bucket policy, thus it allows HTTP requests."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_comply_policy(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        ssl_policy = """
{
  "Version": "2012-10-17",
  "Id": "PutObjPolicy",
  "Statement": [
    {
      "Sid": "s3-bucket-ssl-requests-only",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::bucket_test_us/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
"""
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=ssl_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has a bucket policy to deny requests over insecure transport."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_uncomply_policy(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        ssl_policy = """
{
  "Version": "2012-10-17",
  "Id": "PutObjPolicy",
  "Statement": [
    {
      "Sid": "s3-bucket-ssl-requests-only",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bucket_test_us/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
"""
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=ssl_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} allows requests over insecure transport in the bucket policy."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_uncomply_policy_without_action(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        ssl_policy = """
{
  "Version": "2012-10-17",
  "Id": "PutObjPolicy",
  "Statement": [
    {
      "Sid": "s3-bucket-ssl-requests-only",
      "Effect": "Deny",
      "Principal": "*",
      "Resource": "arn:aws:s3:::bucket_test_us/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
"""
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=ssl_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                check = s3_bucket_secure_transport_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} allows requests over insecure transport in the bucket policy."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @pytest.mark.parametrize(
        "statement",
        [
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="deny-scoped-to-one-principal",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="deny-with-not-principal",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "NotResource": "arn:aws:s3:::bucket_test_us/public/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="deny-with-not-resource",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:Get*",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="action-wildcard-not-covering-put-object",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObjectTagging",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="action-sharing-put-object-prefix",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"},
                        "StringEquals": {"aws:SourceVpce": "vpce-1a2b3c4d"},
                    },
                },
                id="deny-narrowed-by-extra-condition",
            ),
            pytest.param(
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::bucket_test_us/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                },
                id="deny-on-secure-transport",
            ),
        ],
    )
    @mock_aws
    def test_bucket_policy_does_not_deny_insecure_transport_for_everyone(
        self, statement
    ):
        bucket_name_us = "bucket_test_us"
        result = self._execute_check_with_policy(
            bucket_name_us, {"Version": "2012-10-17", "Statement": [statement]}
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"S3 Bucket {bucket_name_us} allows requests over insecure transport in the bucket policy."
        )
        assert result[0].resource_id == bucket_name_us

    @pytest.mark.parametrize(
        "policy",
        [
            pytest.param(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": "arn:aws:s3:::bucket_test_us/*",
                            "Condition": {"Bool": {"aws:SecureTransport": ["false"]}},
                        }
                    ],
                },
                id="condition-value-as-list",
            ),
            pytest.param(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": "arn:aws:s3:::bucket_test_us/*",
                            "Condition": {"Bool": {"aws:SecureTransport": False}},
                        }
                    ],
                },
                id="condition-value-as-boolean",
            ),
            pytest.param(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": {"AWS": "*"},
                            "Action": ["s3:GetObject", "s3:Put*"],
                            "Resource": "arn:aws:s3:::bucket_test_us/*",
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ],
                },
                id="public-aws-principal-and-action-wildcard",
            ),
            pytest.param(
                {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "*",
                        "Resource": [
                            "arn:aws:s3:::bucket_test_us",
                            "arn:aws:s3:::bucket_test_us/*",
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    },
                },
                id="single-statement-object",
            ),
        ],
    )
    @mock_aws
    def test_bucket_policy_denies_insecure_transport_for_everyone(self, policy):
        bucket_name_us = "bucket_test_us"
        result = self._execute_check_with_policy(bucket_name_us, policy)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"S3 Bucket {bucket_name_us} has a bucket policy to deny requests over insecure transport."
        )
        assert result[0].resource_id == bucket_name_us

    @staticmethod
    def _execute_check_with_policy(bucket_name, policy):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name, Policy=json.dumps(policy)
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy.s3_client",
                new=S3(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_bucket_secure_transport_policy.s3_bucket_secure_transport_policy import (
                    s3_bucket_secure_transport_policy,
                )

                return s3_bucket_secure_transport_policy().execute()
