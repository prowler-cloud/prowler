from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.waf.waf_service import WAF

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

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
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.waf.waf_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WAF_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test WAF Service
    def test_service(self):
        # WAF client for this test class
        audit_info = self.set_mocked_audit_info()
        waf = WAF(audit_info)
        assert waf.service == "waf-regional"

    # Test WAF Client
    def test_client(self):
        # WAF client for this test class
        audit_info = self.set_mocked_audit_info()
        waf = WAF(audit_info)
        for regional_client in waf.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFRegional"

    # Test WAF Session
    def test__get_session__(self):
        # WAF client for this test class
        audit_info = self.set_mocked_audit_info()
        waf = WAF(audit_info)
        assert waf.session.__class__.__name__ == "Session"

    # Test WAF Describe Web ACLs
    def test__list_web_acls__(self):
        # WAF client for this test class
        audit_info = self.set_mocked_audit_info()
        waf = WAF(audit_info)
        assert len(waf.web_acls) == 1
        assert waf.web_acls[0].name == "my-web-acl"
        assert waf.web_acls[0].region == AWS_REGION
        assert waf.web_acls[0].id == "my-web-acl-id"

    # Test WAF Describe Web ACLs Resources
    def test__list_resources_for_web_acl__(self):
        # WAF client for this test class
        audit_info = self.set_mocked_audit_info()
        waf = WAF(audit_info)
        assert len(waf.web_acls) == 1
        assert len(waf.web_acls[0].albs) == 1
        assert "alb-arn" in waf.web_acls[0].albs
