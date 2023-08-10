from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_cloudfront
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    CloudFront,
    GeoRestrictionType,
    ViewerProtocolPolicy,
)
from prowler.providers.common.models import Audit_Metadata

# Mock Test Region
AWS_REGION = "eu-west-1"


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


# PENDING PR TO GET THE PARAMETERS USING MOTO


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_CloudFront_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=DEFAULT_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test CloudFront Client
    @mock_cloudfront
    def test__get_client__(self):
        cloudfront = CloudFront(self.set_mocked_audit_info())
        assert cloudfront.client.__class__.__name__ == "CloudFront"

    # Test CloudFront Session
    @mock_cloudfront
    def test__get_session__(self):
        cloudfront = CloudFront(self.set_mocked_audit_info())
        assert cloudfront.session.__class__.__name__ == "Session"

    # Test CloudFront Service
    @mock_cloudfront
    def test__get_service__(self):
        cloudfront = CloudFront(self.set_mocked_audit_info())
        assert cloudfront.service == "cloudfront"

    @mock_cloudfront
    def test__list_distributions__zero(self):
        cloudfront = CloudFront(self.set_mocked_audit_info())

        assert len(cloudfront.distributions) == 0

    @mock_cloudfront
    def test__list_distributions__complete(self):
        cloudfront_client = client("cloudfront")
        config = example_distribution_config("ref")
        response = cloudfront_client.create_distribution(DistributionConfig=config)
        cloudfront_distribution_id = response["Distribution"]["Id"]
        cloudfront_distribution_arn = response["Distribution"]["ARN"]
        cloudfront = CloudFront(self.set_mocked_audit_info())

        assert len(cloudfront.distributions) == 1
        assert (
            cloudfront.distributions[cloudfront_distribution_id].arn
            == cloudfront_distribution_arn
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].id
            == cloudfront_distribution_id
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].region
            == self.set_mocked_audit_info().audit_session.region_name
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].logging_enabled is True
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].origins
            == cloudfront_client.get_distribution(Id=cloudfront_distribution_id)[
                "Distribution"
            ]["DistributionConfig"]["Origins"]["Items"]
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].geo_restriction_type
            == GeoRestrictionType.blacklist
        )
        assert (
            cloudfront.distributions[cloudfront_distribution_id].web_acl_id
            == "test-web-acl"
        )
        assert (
            cloudfront.distributions[
                cloudfront_distribution_id
            ].default_cache_config.realtime_log_config_arn
            == "test-log-arn"
        )
        assert (
            cloudfront.distributions[
                cloudfront_distribution_id
            ].default_cache_config.viewer_protocol_policy
            == ViewerProtocolPolicy.https_only
        )
        assert (
            cloudfront.distributions[
                cloudfront_distribution_id
            ].default_cache_config.field_level_encryption_id
            == "enabled"
        )

        assert cloudfront.distributions[cloudfront_distribution_id].tags == [
            {"Key": "test", "Value": "test"},
        ]
