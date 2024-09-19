from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    CloudFront,
    DefaultCacheConfigBehaviour,
    Distribution,
    GeoRestrictionType,
    Origin,
    SSLSupportMethod,
    ViewerProtocolPolicy,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


def example_distribution_config(ref):
    """Return a basic example distribution config for use in tests."""
    return {
        "CallerReference": ref,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "asdf.s3.us-east-1.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                },
            ],
        },
        "OriginGroups": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin-group1",
                    "FailoverCriteria": {
                        "StatusCodes": {"Quantity": 1, "Items": [500]}
                    },
                    "Members": {
                        "Quantity": 2,
                        "Items": [
                            {
                                "OriginId": "origin1",
                            },
                            {
                                "OriginId": "origin2",
                            },
                        ],
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "MinTTL": 10,
            "ForwardedValues": {
                "QueryString": False,
                "Cookies": {"Forward": "none"},
            },
        },
        "ViewerCertificate": {
            "SSLSupportMethod": "static-ip",
            "Certificate": "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
        },
        "Comment": "an optional comment that's not actually optional",
        "Enabled": False,
    }


# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "GetDistributionConfig":
        if kwarg["Id"]:
            return {
                "DistributionConfig": {
                    "Origins": {"Quantity": 123, "Items": []},
                    "OriginGroups": {"Quantity": 123, "Items": []},
                    "DefaultCacheBehavior": {
                        "TargetOriginId": "",
                        "TrustedSigners": {
                            "Enabled": False,
                            "Quantity": 123,
                            "Items": [
                                "",
                            ],
                        },
                        "TrustedKeyGroups": {
                            "Enabled": False,
                            "Quantity": 123,
                            "Items": [
                                "",
                            ],
                        },
                        "ViewerProtocolPolicy": "https-only",
                        "AllowedMethods": {
                            "Quantity": 123,
                            "Items": [
                                "GET",
                            ],
                            "CachedMethods": {
                                "Quantity": 123,
                                "Items": [
                                    "GET",
                                ],
                            },
                        },
                        "SmoothStreaming": False,
                        "Compress": False,
                        "LambdaFunctionAssociations": {},
                        "FunctionAssociations": {},
                        "FieldLevelEncryptionId": "enabled",
                        "RealtimeLogConfigArn": "test-log-arn",
                        "CachePolicyId": "",
                        "OriginRequestPolicyId": "",
                        "ResponseHeadersPolicyId": "",
                        "ForwardedValues": {
                            "QueryString": False,
                            "Cookies": {},
                            "Headers": {},
                            "QueryStringCacheKeys": {},
                        },
                        "MinTTL": 123,
                        "DefaultTTL": 123,
                        "MaxTTL": 123,
                    },
                    "CacheBehaviors": {},
                    "CustomErrorResponses": {},
                    "Comment": "",
                    "Logging": {
                        "Enabled": True,
                        "IncludeCookies": False,
                        "Bucket": "",
                        "Prefix": "",
                    },
                    "PriceClass": "PriceClass_All",
                    "Enabled": False,
                    "ViewerCertificate": {},
                    "Restrictions": {
                        "GeoRestriction": {
                            "RestrictionType": "blacklist",
                            "Quantity": 123,
                            "Items": [
                                "",
                            ],
                        }
                    },
                    "WebACLId": "test-web-acl",
                    "HttpVersion": "http2and3",
                    "IsIPV6Enabled": False,
                },
                "ETag": "",
            }
    if operation_name == "ListTagsForResource":
        return {
            "Tags": {
                "Items": [
                    {"Key": "test", "Value": "test"},
                ]
            }
        }
    return make_api_call(self, operation_name, kwarg)


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_CloudFront_Service:
    # Test CloudFront Client
    @mock_aws
    def test_get_client(self):
        cloudfront = CloudFront(set_mocked_aws_provider())
        assert cloudfront.client.__class__.__name__ == "CloudFront"

    # Test CloudFront Session
    @mock_aws
    def test__get_session__(self):
        cloudfront = CloudFront(set_mocked_aws_provider())
        assert cloudfront.session.__class__.__name__ == "Session"

    # Test CloudFront Service
    @mock_aws
    def test__get_service__(self):
        cloudfront = CloudFront(set_mocked_aws_provider())
        assert cloudfront.service == "cloudfront"

    @mock_aws
    def test_list_distributionszero(self):
        cloudfront = CloudFront(set_mocked_aws_provider())

        assert len(cloudfront.distributions) == 0

    def test_list_distributionscomplete(self):
        from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER

        DISTRIBUTION_ID = "E27LVI50CSW06W"
        DISTRIBUTION_ARN = (
            f"arn:aws:cloudfront::{AWS_ACCOUNT_NUMBER}:distribution/{DISTRIBUTION_ID}"
        )
        REGION = "us-east-1"
        LOGGING_ENABLED = True
        ORIGINS = [
            Origin(
                id="origin1",
                domain_name="asdf.s3.us-east-1.amazonaws.com",
                origin_protocol_policy="",
                origin_ssl_protocols=[],
            ),
        ]
        DEFAULT_CACHE_CONFIG = DefaultCacheConfigBehaviour(
            realtime_log_config_arn="test-log-arn",
            viewer_protocol_policy=ViewerProtocolPolicy.https_only,
            field_level_encryption_id="enabled",
        )
        GEO_RESTRICTION_TYPE = GeoRestrictionType.blacklist
        WEB_ACL_ID = "test-web-acl"
        TAGS = [
            {"Key": "test", "Value": "test"},
        ]
        SSL_SUPPORT_METHOD = SSLSupportMethod.sni_only
        CERTIFICATE = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"

        cloudfront = mock.MagicMock
        cloudfront.distributions = {
            DISTRIBUTION_ID: Distribution(
                arn=DISTRIBUTION_ARN,
                id=DISTRIBUTION_ID,
                region=REGION,
                logging_enabled=LOGGING_ENABLED,
                origins=ORIGINS,
                default_cache_config=DEFAULT_CACHE_CONFIG,
                geo_restriction_type=GEO_RESTRICTION_TYPE,
                web_acl_id=WEB_ACL_ID,
                tags=TAGS,
                ssl_support_method=SSL_SUPPORT_METHOD,
                certificate=CERTIFICATE,
            )
        }

        assert len(cloudfront.distributions) == 1
        assert cloudfront.distributions[DISTRIBUTION_ID].arn == DISTRIBUTION_ARN
        assert cloudfront.distributions[DISTRIBUTION_ID].id == DISTRIBUTION_ID
        assert cloudfront.distributions[DISTRIBUTION_ID].region == AWS_REGION_US_EAST_1
        assert (
            cloudfront.distributions[DISTRIBUTION_ID].logging_enabled is LOGGING_ENABLED
        )
        for origin in cloudfront.distributions[DISTRIBUTION_ID].origins:
            assert origin.id == "origin1"
            assert origin.domain_name == "asdf.s3.us-east-1.amazonaws.com"
            assert origin.origin_protocol_policy == ""
            assert origin.origin_ssl_protocols == []
        assert (
            cloudfront.distributions[DISTRIBUTION_ID].geo_restriction_type
            == GEO_RESTRICTION_TYPE
        )
        assert cloudfront.distributions[DISTRIBUTION_ID].web_acl_id == "test-web-acl"
        assert (
            cloudfront.distributions[
                DISTRIBUTION_ID
            ].default_cache_config.realtime_log_config_arn
            == DEFAULT_CACHE_CONFIG.realtime_log_config_arn
        )
        assert (
            cloudfront.distributions[
                DISTRIBUTION_ID
            ].default_cache_config.viewer_protocol_policy
            == DEFAULT_CACHE_CONFIG.viewer_protocol_policy
        )
        assert (
            cloudfront.distributions[
                DISTRIBUTION_ID
            ].default_cache_config.field_level_encryption_id
            == DEFAULT_CACHE_CONFIG.field_level_encryption_id
        )
        assert cloudfront.distributions[DISTRIBUTION_ID].tags == TAGS
