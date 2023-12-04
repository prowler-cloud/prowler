from json import dumps
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.opensearch.opensearch_service import (
    OpenSearchService,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

test_domain_name = "test"
domain_arn = f"arn:aws:es:us-west-2:{AWS_ACCOUNT_NUMBER}:domain/{test_domain_name}"

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
                    "vpc": "vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.us-east-1.es.amazonaws.com"
                },
                "EngineVersion": "opensearch-version1",
                "VPCOptions": {
                    "VPCId": "test-vpc-id",
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
                "AdvancedSecurityOptions": {"InternalUserDatabaseEnabled": True},
            }
        }
    if operation_name == "ListTags":
        return {
            "TagList": [
                {"Key": "test", "Value": "test"},
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_OpenSearchService_Service:
    # Test OpenSearchService Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        assert opensearch.service == "opensearch"

    # Test OpenSearchService_ client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        for reg_client in opensearch.regional_clients.values():
            assert reg_client.__class__.__name__ == "OpenSearchService"

    # Test OpenSearchService session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        assert opensearch.session.__class__.__name__ == "Session"

    # Test OpenSearchService list domains names
    def test__list_domain_names__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[0].name == test_domain_name
        assert opensearch.opensearch_domains[0].region == AWS_REGION_EU_WEST_1

    # Test OpenSearchService describ domain config
    def test__describe_domain_config__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[0].name == test_domain_name
        assert opensearch.opensearch_domains[0].region == AWS_REGION_EU_WEST_1
        assert opensearch.opensearch_domains[0].access_policy
        assert opensearch.opensearch_domains[0].logging[0].name == "SEARCH_SLOW_LOGS"
        assert opensearch.opensearch_domains[0].logging[0].enabled
        assert opensearch.opensearch_domains[0].logging[1].name == "INDEX_SLOW_LOGS"
        assert opensearch.opensearch_domains[0].logging[1].enabled
        assert opensearch.opensearch_domains[0].logging[2].name == "AUDIT_LOGS"
        assert opensearch.opensearch_domains[0].logging[2].enabled

    # Test OpenSearchService describ domain
    def test__describe_domain__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        opensearch = OpenSearchService(audit_info)
        assert len(opensearch.opensearch_domains) == 1
        assert opensearch.opensearch_domains[0].name == test_domain_name
        assert opensearch.opensearch_domains[0].region == AWS_REGION_EU_WEST_1
        assert opensearch.opensearch_domains[0].arn == domain_arn
        assert opensearch.opensearch_domains[0].access_policy
        assert (
            opensearch.opensearch_domains[0].endpoint_vpc
            == "vpc-endpoint-h2dsd34efgyghrtguk5gt6j2foh4.us-east-1.es.amazonaws.com"
        )
        assert opensearch.opensearch_domains[0].vpc_id == "test-vpc-id"
        assert opensearch.opensearch_domains[0].cognito_options
        assert opensearch.opensearch_domains[0].encryption_at_rest
        assert opensearch.opensearch_domains[0].node_to_node_encryption
        assert opensearch.opensearch_domains[0].enforce_https
        assert opensearch.opensearch_domains[0].internal_user_database
        assert opensearch.opensearch_domains[0].update_available
        assert opensearch.opensearch_domains[0].version == "opensearch-version1"
        assert opensearch.opensearch_domains[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
