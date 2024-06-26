from unittest.mock import patch

import botocore
import yaml
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.ssm.ssm_service import SSM, ResourceStatus
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListResourceComplianceSummaries":
        return {
            "ResourceComplianceSummaryItems": [
                {
                    "ComplianceType": "Association",
                    "ResourceType": "ManagedInstance",
                    "ResourceId": "i-1234567890abcdef0",
                    "Status": "COMPLIANT",
                    "OverallSeverity": "UNSPECIFIED",
                    "ExecutionSummary": {"ExecutionTime": 1550509273.0},
                    "CompliantSummary": {
                        "CompliantCount": 2,
                        "SeveritySummary": {
                            "CriticalCount": 0,
                            "HighCount": 0,
                            "MediumCount": 0,
                            "LowCount": 0,
                            "InformationalCount": 0,
                            "UnspecifiedCount": 2,
                        },
                    },
                    "NonCompliantSummary": {
                        "NonCompliantCount": 0,
                        "SeveritySummary": {
                            "CriticalCount": 0,
                            "HighCount": 0,
                            "MediumCount": 0,
                            "LowCount": 0,
                            "InformationalCount": 0,
                            "UnspecifiedCount": 0,
                        },
                    },
                },
            ],
        }
    if operation_name == "DescribeInstanceInformation":
        return {
            "InstanceInformationList": [
                {
                    "InstanceId": "test-instance-id",
                },
            ],
        }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


# SSM Document YAML Template
ssm_document_yaml = """
schemaVersion: "2.2"
description: "Sample Yaml"
parameters:
  Parameter1:
    type: "Integer"
    default: 3
    description: "Command Duration."
    allowedValues: [1,2,3,4]
  Parameter2:
    type: "String"
    default: "def"
    description:
    allowedValues: ["abc", "def", "ghi"]
    allowedPattern: r"^[a-zA-Z0-9_-.]{3,128}$"
  Parameter3:
    type: "Boolean"
    default: false
    description: "A boolean"
    allowedValues: [True, False]
  Parameter4:
    type: "StringList"
    default: ["abc", "def"]
    description: "A string list"
  Parameter5:
    type: "StringMap"
    default:
      NotificationType: Command
      NotificationEvents:
      - Failed
      NotificationArn: "$dependency.topicArn"
    description:
  Parameter6:
    type: "MapList"
    default:
    - DeviceName: "/dev/sda1"
      Ebs:
        VolumeSize: '50'
    - DeviceName: "/dev/sdm"
      Ebs:
        VolumeSize: '100'
    description:
mainSteps:
  - action: "aws:runShellScript"
    name: "sampleCommand"
    inputs:
      runCommand:
        - "echo hi"
"""


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SSM_Service:
    # Test SSM Client
    @mock_aws
    def test__get_client__(self):
        ssm = SSM(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert ssm.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__ == "SSM"

    # Test SSM Session
    @mock_aws
    def test__get_session__(self):
        ssm = SSM(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert ssm.session.__class__.__name__ == "Session"

    # Test SSM Service
    @mock_aws
    def test__get_service__(self):
        ssm = SSM(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert ssm.service == "ssm"

    @mock_aws
    def test__list_documents__(self):
        # Create SSM Document
        ssm_client = client("ssm", region_name=AWS_REGION_US_EAST_1)
        ssm_document_name = "test-document"
        _ = ssm_client.create_document(
            Content=ssm_document_yaml,
            Name=ssm_document_name,
            DocumentType="Command",
            DocumentFormat="YAML",
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        # Add permissions
        ssm_client.modify_document_permission(
            Name=ssm_document_name,
            PermissionType="Share",
            AccountIdsToAdd=[AWS_ACCOUNT_NUMBER],
        )

        ssm = SSM(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        document_arn = f"arn:aws:ssm:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:document/{ssm_document_name}"

        assert len(ssm.documents) == 1
        assert ssm.documents
        assert ssm.documents[document_arn]
        assert ssm.documents[document_arn].arn == document_arn
        assert ssm.documents[document_arn].name == ssm_document_name
        assert ssm.documents[document_arn].region == AWS_REGION_US_EAST_1
        assert ssm.documents[document_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert ssm.documents[document_arn].content == yaml.safe_load(ssm_document_yaml)
        assert ssm.documents[document_arn].account_owners == [AWS_ACCOUNT_NUMBER]

    @mock_aws
    def test__list_resource_compliance_summaries__(self):
        ssm = SSM(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        instance_id = "i-1234567890abcdef0"
        assert len(ssm.compliance_resources) == 1
        assert ssm.compliance_resources
        assert ssm.compliance_resources[instance_id]
        assert ssm.compliance_resources[instance_id].id == instance_id
        assert ssm.compliance_resources[instance_id].region == AWS_REGION_US_EAST_1
        assert ssm.compliance_resources[instance_id].status == ResourceStatus.COMPLIANT
