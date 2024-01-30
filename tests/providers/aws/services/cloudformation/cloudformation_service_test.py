import datetime
import json
from unittest.mock import patch

import boto3
import botocore
from dateutil.tz import tzutc
from moto import mock_aws

from prowler.providers.aws.services.cloudformation.cloudformation_service import (
    CloudFormation,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

# Dummy CloudFormation Template
dummy_template = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Stack 1",
    "Resources": {
        "EC2Instance1": {
            "Type": "AWS::EC2::Instance",
            "Properties": {
                "ImageId": "EXAMPLE_AMI_ID",
                "KeyName": "dummy",
                "InstanceType": "t2.micro",
                "Tags": [
                    {"Key": "Description", "Value": "Test tag"},
                    {"Key": "Name", "Value": "Name tag for tests"},
                ],
            },
        }
    },
}


# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "CreateStack":
        return {
            "StackId": "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
        }
    if operation_name == "DescribeStacks":
        if "StackName" in kwarg:
            return {
                "Stacks": [
                    {
                        "StackId": "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                        "StackName": "Test-Stack",
                        "Description": "Stack 1",
                        "Parameters": [],
                        "CreationTime": datetime.datetime(
                            2022, 11, 7, 9, 33, 51, tzinfo=tzutc()
                        ),
                        "StackStatus": "CREATE_COMPLETE",
                        "DisableRollback": False,
                        "NotificationARNs": [],
                        "Outputs": [
                            {
                                "OutputKey": "TestOutput1",
                                "OutputValue": "TestValue1",
                                "Description": "Test Output Description.",
                            }
                        ],
                        "RoleARN": "arn:aws:iam::123456789012:role/moto",
                        "EnableTerminationProtection": True,
                        "Tags": [
                            {"Key": "Tag1", "Value": "Value1"},
                            {"Key": "Tag2", "Value": "Value2"},
                        ],
                    }
                ]
            }
        # Return all Stacks
        else:
            return {
                "Stacks": [
                    {
                        "StackId": "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                        "StackName": "Test-Stack",
                        "Description": "Stack 1",
                        "Parameters": [],
                        "CreationTime": datetime.datetime(
                            2022, 11, 7, 9, 33, 51, tzinfo=tzutc()
                        ),
                        "StackStatus": "CREATE_COMPLETE",
                        "DisableRollback": False,
                        "NotificationARNs": [],
                        "Outputs": [
                            {
                                "OutputKey": "TestOutput1",
                                "OutputValue": "TestValue1",
                                "Description": "Test Output Description.",
                            }
                        ],
                        "RoleARN": "arn:aws:iam::123456789012:role/moto",
                        "Tags": [
                            {"Key": "Tag1", "Value": "Value1"},
                            {"Key": "Tag2", "Value": "Value2"},
                        ],
                    }
                ]
            }

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_CloudFormation_Service:
    # Test CloudFormation Client
    @mock_aws
    def test__get_client__(self):
        cloudformation = CloudFormation(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        )
        assert (
            cloudformation.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "CloudFormation"
        )

    # Test CloudFormation Service
    @mock_aws
    def test__get_service__(self):
        cloudformation = CloudFormation(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        )
        assert (
            cloudformation.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "CloudFormation"
        )

    # Test CloudFormation Session
    @mock_aws
    def test__get_session__(self):
        cloudformation = CloudFormation(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        )
        assert cloudformation.session.__class__.__name__ == "Session"

    @mock_aws
    def test__describe_stacks__(self):
        cloudformation_client = boto3.client(
            "cloudformation", region_name=AWS_REGION_EU_WEST_1
        )
        stack_arn = cloudformation_client.create_stack(
            StackName="Test-Stack",
            TemplateBody=json.dumps(dummy_template),
            RoleARN=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/moto",
            Tags=[
                {"Key": "Tag1", "Value": "Value1"},
                {"Key": "Tag2", "Value": "Value2"},
            ],
            EnableTerminationProtection=True,
            Outputs=[
                {
                    "OutputKey": "TestOutput1",
                    "OutputValue": "TestValue1",
                    "Description": "Test Output Description.",
                }
            ],
        )

        cloudformation = CloudFormation(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        )
        assert len(cloudformation.stacks) == 1
        assert cloudformation.stacks[0].arn == stack_arn["StackId"]
        assert cloudformation.stacks[0].name == "Test-Stack"
        assert cloudformation.stacks[0].outputs == ["TestOutput1:TestValue1"]
        assert cloudformation.stacks[0].enable_termination_protection is True
        assert cloudformation.stacks[0].is_nested_stack is False
        assert cloudformation.stacks[0].root_nested_stack == ""
        assert cloudformation.stacks[0].region == AWS_REGION_EU_WEST_1
        assert cloudformation.stacks[0].tags == [
            {"Key": "Tag1", "Value": "Value1"},
            {"Key": "Tag2", "Value": "Value2"},
        ]
