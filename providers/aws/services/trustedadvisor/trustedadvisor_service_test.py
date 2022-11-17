from unittest.mock import patch

import botocore
from boto3 import session
from moto import mock_support

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.trustedadvisor.trustedadvisor_service import TrustedAdvisor

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeTrustedAdvisorCheckResult":
        return {}
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "providers.aws.services.trustedadvisor.trustedadvisor_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_TrustedAdvisor_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
        )
        return audit_info

    # Test TrustedAdvisor Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.service == "support"

    # Test TrustedAdvisor client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        trustedadvisor = TrustedAdvisor(audit_info)
        for reg_client in trustedadvisor.regional_clients.values():
            assert reg_client.__class__.__name__ == "Support"

    # Test TrustedAdvisor session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.session.__class__.__name__ == "Session"

    @mock_support
    # Test TrustedAdvisor session
    def test__describe_trusted_advisor_checks__(self):

        audit_info = self.set_mocked_audit_info()
        trustedadvisor = TrustedAdvisor(audit_info)
        assert len(trustedadvisor.checks) == 104  # Default checks
        assert trustedadvisor.checks[0].region == AWS_REGION
