from unittest.mock import patch

import botocore
from boto3 import session
from moto import mock_support

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    TrustedAdvisor,
)
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeTrustedAdvisorCheckResult":
        return {}
    if operation_name == "DescribeServices":
        return {
            "services": [
                {
                    "code": "amazon-marketplace",
                    "name": "Marketplace",
                    "categories": [
                        {
                            "code": "general-marketplace-seller-inquiry",
                            "name": "General Marketplace Seller Inquiry",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_TrustedAdvisor_Service:
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

    # Test TrustedAdvisor Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.service == "support"

    # Test TrustedAdvisor client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.client.__class__.__name__ == "Support"

    # Test TrustedAdvisor session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.session.__class__.__name__ == "Session"

    @mock_support
    # Test TrustedAdvisor session
    def test__describe_trusted_advisor_checks__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        trustedadvisor = TrustedAdvisor(audit_info)
        assert trustedadvisor.premium_support.enabled
        assert len(trustedadvisor.checks) == 104  # Default checks
        assert trustedadvisor.checks[0].region == AWS_REGION
