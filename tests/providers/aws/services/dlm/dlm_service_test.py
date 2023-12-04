import botocore
from boto3 import session
from mock import patch

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.dlm.dlm_service import DLM, LifecyclePolicy
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

LIFECYCLE_POLICY_ID = "policy-XXXXXXXXXXXX"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "GetLifecyclePolicies":
        return {
            "Policies": [
                {
                    "PolicyId": "policy-XXXXXXXXXXXX",
                    "Description": "test",
                    "State": "ENABLED",
                    "Tags": {"environment": "dev"},
                    "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
                }
            ]
        }

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DLM_Service:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test DLM Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        dlm = DLM(audit_info)
        assert dlm.service == "dlm"

    # Test DLM Client
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        dlm = DLM(audit_info)
        assert dlm.client.__class__.__name__ == "DLM"

    # Test DLM Session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        dlm = DLM(audit_info)
        assert dlm.session.__class__.__name__ == "Session"

    # Test DLM Session
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        dlm = DLM(audit_info)
        assert dlm.audited_account == AWS_ACCOUNT_NUMBER

    # Test DLM Get DLM Contacts
    def test_get_lifecycle_policies(self):
        # DLM client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        dlm = DLM(audit_info)
        assert dlm.lifecycle_policies == {
            AWS_REGION: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={"environment": "dev"},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }
