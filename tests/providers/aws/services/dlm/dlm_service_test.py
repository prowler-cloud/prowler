import botocore
from mock import patch

from prowler.providers.aws.services.dlm.dlm_service import DLM, LifecyclePolicy
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


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
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DLM_Service:
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
            AWS_REGION_EU_WEST_1: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={"environment": "dev"},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }
