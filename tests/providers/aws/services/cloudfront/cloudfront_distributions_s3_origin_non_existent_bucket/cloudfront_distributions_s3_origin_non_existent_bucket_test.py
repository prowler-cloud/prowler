from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudfront.cloudfront_service import CloudFront
from prowler.providers.aws.services.s3.s3_service import S3
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, set_mocked_aws_provider

REGION = "eu-west-1"
DISTRIBUTION_ID = "E27LVI50CSW06W"
DISTRIBUTION_ARN = (
    f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListDistributions":
        return {
            "DistributionList": {
                "Marker": "",
                "NextMarker": None,
                "MaxItems": 100,
                "IsTruncated": False,
                "Quantity": 1,
                "Items": [
                    {
                        "Id": DISTRIBUTION_ID,
                        "ARN": "arn:aws:cloudfront::123456789012:distribution/E27LVI50CSW06W",
                        "Status": "Deployed",
                        "LastModifiedTime": "2023-09-10T18:43:12Z",
                        "DomainName": "d111111abcdef8.cloudfront.net",
                        "Aliases": {"Quantity": 0, "Items": []},
                        "Origins": {
                            "Quantity": 1,
                            "Items": [
                                {
                                    "Id": "test-bucket",
                                    "DomainName": "test-bucket.s3.eu-west-1.amazonaws.com",
                                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                                }
                            ],
                        },
                        "DefaultCacheBehavior": {
                            "TargetOriginId": "test-bucket",
                            "ForwardedValues": {
                                "QueryString": False,
                                "Cookies": {"Forward": "none"},
                            },
                            "TrustedSigners": {"Enabled": False, "Quantity": 0},
                            "ViewerProtocolPolicy": "allow-all",
                            "MinTTL": 0,
                        },
                        "Comment": "test distribution",
                        "Enabled": True,
                        "PriceClass": "PriceClass_All",
                        "ViewerCertificate": {
                            "CloudFrontDefaultCertificate": True,
                            "CertificateSource": "cloudfront",
                        },
                        "Restrictions": {
                            "GeoRestriction": {"RestrictionType": "none", "Quantity": 0}
                        },
                        "WebACLId": "",
                        "HttpVersion": "http2",
                        "IsIPV6Enabled": True,
                    }
                ],
            }
        }
    return orig(self, operation_name, kwarg)


class Test_cloudfront_s3_origin_non_existent_bucket:
    @mock_aws
    def test_no_distributions(self):
        aws_provider = set_mocked_aws_provider([REGION])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_client",
            new=CloudFront(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_distribution_nonexistent_origins(self):
        aws_provider = set_mocked_aws_provider([REGION])

        # Name of the nonexistent bucket
        bucket_name = "test-bucket"

        # Create CloudFront Distribution
        cloudfront_client = client("cloudfront")
        domain = f"{bucket_name}.s3.{REGION}.amazonaws.com"
        cloudfront_client.create_distribution(
            DistributionConfig={
                "CallerReference": "test",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": bucket_name,
                            "DomainName": domain,
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": bucket_name,
                    "ViewerProtocolPolicy": "allow-all",
                    "TrustedSigners": {"Enabled": False, "Quantity": 0},
                    "ForwardedValues": {
                        "QueryString": False,
                        "Cookies": {"Forward": "none"},
                    },
                    "MinTTL": 0,
                },
                "Comment": "test distribution",
                "Enabled": True,
            }
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_client",
            new=CloudFront(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} has non-existent S3 buckets as origins: {bucket_name}"
            )

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_distribution_no_nonexistent_origins(self):
        aws_provider = set_mocked_aws_provider([REGION])

        # Create S3 Bucket
        s3_client = client("s3", region_name=REGION)
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": REGION}
        )

        # Create CloudFront Distribution
        cloudfront_client = client("cloudfront")
        domain = f"{bucket_name}.s3.{REGION}.amazonaws.com"
        cloudfront_client.create_distribution(
            DistributionConfig={
                "CallerReference": "test",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": bucket_name,
                            "DomainName": domain,
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": bucket_name,
                    "ViewerProtocolPolicy": "allow-all",
                    "TrustedSigners": {"Enabled": False, "Quantity": 0},
                    "ForwardedValues": {
                        "QueryString": False,
                        "Cookies": {"Forward": "none"},
                    },
                    "MinTTL": 0,
                },
                "Comment": "test distribution",
                "Enabled": True,
            }
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_client",
            new=CloudFront(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudfront.cloudfront_distributions_s3_origin_non_existent_bucket.cloudfront_distributions_s3_origin_non_existent_bucket import (
                cloudfront_distributions_s3_origin_non_existent_bucket,
            )

            check = cloudfront_distributions_s3_origin_non_existent_bucket()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == REGION
            assert result[0].resource_arn == DISTRIBUTION_ARN
            assert result[0].resource_id == DISTRIBUTION_ID
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFront Distribution {DISTRIBUTION_ID} does not have non-existent S3 buckets as origins."
            )
