from unittest.mock import patch

import botocore

from prowler.providers.aws.services.waf.waf_service import WAF
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

# Mocking WAF-Regional Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": "my-web-acl-id", "Name": "my-web-acl"},
            ]
        }
    if operation_name == "ListResourcesForWebACL":
        return {
            "ResourceArns": [
                "alb-arn",
            ]
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WAF_Service:
    # Test WAF Service
    def test_service(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        waf = WAF(aws_provider)
        assert waf.service == "waf-regional"

    # Test WAF Client
    def test_client(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        waf = WAF(aws_provider)
        for regional_client in waf.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFRegional"

    # Test WAF Session
    def test__get_session__(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        waf = WAF(aws_provider)
        assert waf.session.__class__.__name__ == "Session"

    # Test WAF Describe Web ACLs
    def test_list_web_acls(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        waf = WAF(aws_provider)
        waf_arn = "arn:aws:waf-regional:eu-west-1:123456789012:webacl/my-web-acl-id"
        assert len(waf.web_acls) == 1
        assert waf.web_acls[waf_arn].name == "my-web-acl"
        assert waf.web_acls[waf_arn].region == AWS_REGION_EU_WEST_1
        assert waf.web_acls[waf_arn].id == "my-web-acl-id"

    # Test WAF Describe Web ACLs Resources
    def test_list_resources_for_web_acl(self):
        # WAF client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        waf = WAF(aws_provider)
        waf_arn = "arn:aws:waf-regional:eu-west-1:123456789012:webacl/my-web-acl-id"
        assert len(waf.web_acls) == 1
        assert len(waf.web_acls[waf_arn].albs) == 1
        assert "alb-arn" in waf.web_acls[waf_arn].albs

    # Test WAF Get Web ACL
    def test_get_web_acl(self):
        pass
