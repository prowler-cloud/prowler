from json import dumps
from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchService,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_domain_name = "test"
domain_arn = f"arn:aws:es:eu-west-1:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_name}"

policy_data = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["es:*"],
            "Resource": f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_name}/*",
        }
    ],
}

policy_json = dumps(policy_data)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListDomainNames":
        return {
            "DomainNames": [
                {
                    "DomainName": test_domain_name,
                },
            ]
        }
    if operation_name == "DescribeDomainConfig":
        return {
            "DomainConfig": {
                "AccessPolicies": {
                    "Options": policy_json,
                },
                "LogPublishingOptions": {
                    "Options": {
                        "SEARCH_SLOW_LOGS": {"Enabled": True},
                        "INDEX_SLOW_LOGS": {"Enabled": True},
                        "AUDIT_LOGS": {"Enabled": True},
                    },
                },
            }
        }
    if operation_name == "DescribeDomain":
        return {
            "DomainStatus": {
                "ARN": domain_arn,
                "Endpoints": {
                    "vpc": "vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.eu-west-1.es.amazonaws.com"
                },
                "EngineVersion": "opensearch-version1",
                "VPCOptions": {
                    "VPCId": "test-vpc-id",
                },
                "ClusterConfig": {
                    "DedicatedMasterEnabled": True,
                    "DedicatedMasterCount": 1,
                    "DedicatedMasterType": "m3.medium.search",
                    "InstanceCount": 1,
                    "ZoneAwarenessEnabled": True,
                },
                "CognitoOptions": {"Enabled": True},
                "EncryptionAtRestOptions": {"Enabled": True},
                "NodeToNodeEncryptionOptions": {"Enabled": True},
                "AdvancedOptions": {"string": "string"},
                "LogPublishingOptions": {
                    "string": {
                        "CloudWatchLogsLogGroupArn": "string",
                        "Enabled": True | False,
                    }
                },
                "ServiceSoftwareOptions": {"UpdateAvailable": True},
                "DomainEndpointOptions": {"EnforceHTTPS": True},
                "AdvancedSecurityOptions": {
                    "Enabled": True,
                    "InternalUserDatabaseEnabled": True,
                    "SAMLOptions": {"Enabled": True},
                },
            }
        }
    if operation_name == "ListTags":
        return {
            "TagList": [
                {"Key": "test", "Value": "test"},
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class TestOpenSearchServiceService:
    # Test OpenSearchService Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        assert opensearch.service == "opensearch"

    # Test OpenSearchService_ client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        for reg_client in opensearch.regional_clients.values():
            assert reg_client.__class__.__name__ == "OpenSearchService"

    # Test OpenSearchService session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        assert opensearch.session.__class__.__name__ == "Session"

    # Test OpenSearchService list domains names
    def test_list_domain_names(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[domain_arn].name == test_domain_name
        assert opensearch.opensearch_domains[domain_arn].region == AWS_REGION_EU_WEST_1

    # Test OpenSearchService describe domain config
    def test_describe_domain_config(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[domain_arn].name == test_domain_name
        assert opensearch.opensearch_domains[domain_arn].region == AWS_REGION_EU_WEST_1
        assert opensearch.opensearch_domains[domain_arn].access_policy
        assert (
            opensearch.opensearch_domains[domain_arn].logging[0].name
            == "SEARCH_SLOW_LOGS"
        )
        assert opensearch.opensearch_domains[domain_arn].logging[0].enabled
        assert (
            opensearch.opensearch_domains[domain_arn].logging[1].name
            == "INDEX_SLOW_LOGS"
        )
        assert opensearch.opensearch_domains[domain_arn].logging[1].enabled
        assert opensearch.opensearch_domains[domain_arn].logging[2].name == "AUDIT_LOGS"
        assert opensearch.opensearch_domains[domain_arn].logging[2].enabled

    # Test OpenSearchService describe domain
    @mock_aws
    def test_describe_domain(self):
        aws_provider = set_mocked_aws_provider([])
        opensearch = OpenSearchService(aws_provider)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[domain_arn].name == test_domain_name
        assert opensearch.opensearch_domains[domain_arn].region == AWS_REGION_EU_WEST_1
        assert opensearch.opensearch_domains[domain_arn].arn == domain_arn
        assert opensearch.opensearch_domains[domain_arn].access_policy
        assert opensearch.opensearch_domains[domain_arn].vpc_endpoints == [
            "vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.eu-west-1.es.amazonaws.com"
        ]
        assert opensearch.opensearch_domains[domain_arn].vpc_id == "test-vpc-id"
        assert opensearch.opensearch_domains[domain_arn].cognito_options
        assert opensearch.opensearch_domains[domain_arn].encryption_at_rest
        assert opensearch.opensearch_domains[domain_arn].node_to_node_encryption
        assert opensearch.opensearch_domains[domain_arn].enforce_https
        assert opensearch.opensearch_domains[domain_arn].internal_user_database
        assert opensearch.opensearch_domains[domain_arn].saml_enabled
        assert opensearch.opensearch_domains[domain_arn].update_available
        assert (
            opensearch.opensearch_domains[domain_arn].version == "opensearch-version1"
        )
        assert opensearch.opensearch_domains[domain_arn].instance_count == 1
        assert opensearch.opensearch_domains[domain_arn].zone_awareness_enabled
        assert opensearch.opensearch_domains[domain_arn].dedicated_master_enabled
        assert opensearch.opensearch_domains[domain_arn].dedicated_master_count == 1
        assert opensearch.opensearch_domains[domain_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]
