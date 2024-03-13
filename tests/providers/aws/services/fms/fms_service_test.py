from datetime import datetime
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.fms.fms_service import FMS
from tests.providers.aws.utils import set_mocked_aws_provider

POLICY_ARN = "arn:aws:fms:us-east-1:123456789012:policy/MyFMSManagedPolicy"
POLICY_ID = "12345678-1234-1234-1234-123456789012"
POLICY_NAME = "MyFMSManagedPolicy"
RESOURCE_TYPE = "AWS::EC2::Instance"
SERVICE_TYPE = "WAF"
REMEDIATION_ENABLED = True
DELETE_UNUSED_MANAGED_RESOURCES = True

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListPolicies":
        return {
            "PolicyList": [
                {
                    "DeleteUnusedFMManagedResources": DELETE_UNUSED_MANAGED_RESOURCES,
                    "PolicyArn": POLICY_ARN,
                    "PolicyId": POLICY_ID,
                    "PolicyName": POLICY_NAME,
                    "RemediationEnabled": REMEDIATION_ENABLED,
                    "ResourceType": RESOURCE_TYPE,
                    "SecurityServiceType": SERVICE_TYPE,
                }
            ]
        }
    if operation_name == "ListComplianceStatus":
        return {
            "PolicyComplianceStatusList": [
                {
                    "EvaluationResults": [
                        {
                            "ComplianceStatus": "COMPLIANT",
                            "EvaluationLimitExceeded": False,
                            "ViolatorCount": 10,
                        }
                    ],
                    "IssueInfoMap": {"string": "test"},
                    "LastUpdated": datetime(2024, 1, 1),
                    "MemberAccount": "123456789012",
                    "PolicyId": POLICY_ID,
                    "PolicyName": POLICY_NAME,
                    "PolicyOwner": "123456789011",
                }
            ]
        }

    return make_api_call(self, operation_name, kwargs)


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_FMS_Service:
    def test__get_client__(self):
        aws_provider = set_mocked_aws_provider()
        fms = FMS(aws_provider)
        assert fms.client.__class__.__name__ == "FMS"

    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider()
        fms = FMS(aws_provider)
        assert fms.service == "fms"

    def test__list_policies__(self):
        aws_provider = set_mocked_aws_provider()
        fms = FMS(aws_provider)
        assert len(fms.fms_policies) == 1
        assert fms.fms_admin_account is True
        assert fms.fms_policies[0].arn == POLICY_ARN
        assert fms.fms_policies[0].id == POLICY_ID
        assert fms.fms_policies[0].name == POLICY_NAME
        assert fms.fms_policies[0].resource_type == RESOURCE_TYPE
        assert fms.fms_policies[0].service_type == SERVICE_TYPE
        assert fms.fms_policies[0].remediation_enabled == REMEDIATION_ENABLED
        assert (
            fms.fms_policies[0].delete_unused_managed_resources
            == DELETE_UNUSED_MANAGED_RESOURCES
        )

    def test__list_compliance_status__(self):
        aws_provider = set_mocked_aws_provider()
        fms = FMS(aws_provider)
        assert len(fms.fms_policies) == 1
        assert fms.fms_policies[0].compliance_status[0].status == "COMPLIANT"
        assert fms.fms_policies[0].compliance_status[0].account_id == "123456789012"
        assert fms.fms_policies[0].compliance_status[0].policy_id == POLICY_ID
