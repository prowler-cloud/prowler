import io
import zipfile
from unittest.mock import patch

from boto3 import client, resource
from moto import mock_ec2, mock_iam, mock_lambda, mock_s3, mock_secretsmanager

from prowler.providers.aws.services.secretsmanager.secretsmanager_service import (
    SecretsManager,
)
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SecretsManager_Service:
    # Test SecretsManager Client
    @mock_secretsmanager
    def test__get_client__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        secretsmanager = SecretsManager(audit_info)
        assert (
            secretsmanager.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "SecretsManager"
        )

    # Test SecretsManager Session
    @mock_secretsmanager
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        secretsmanager = SecretsManager(audit_info)
        assert secretsmanager.session.__class__.__name__ == "Session"

    # Test SecretsManager Service
    @mock_secretsmanager
    def test__get_service__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        secretsmanager = SecretsManager(audit_info)
        assert secretsmanager.service == "secretsmanager"

    @mock_secretsmanager
    @mock_lambda
    @mock_ec2
    @mock_iam
    @mock_s3
    def test__list_secrets__(self):
        secretsmanager_client = client(
            "secretsmanager", region_name=AWS_REGION_EU_WEST_1
        )
        # Create Secret
        resp = secretsmanager_client.create_secret(
            Name="test-secret",
            SecretString="test-secret",
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        secret_arn = resp["ARN"]
        secret_name = resp["Name"]
        # Create IAM Lambda Role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        iam_role = iam_client.create_role(
            RoleName="rotation-lambda-role",
            AssumeRolePolicyDocument="test-policy",
            Path="/",
        )["Role"]["Arn"]
        # Create S3 Bucket
        s3_client = resource("s3", region_name=AWS_REGION_EU_WEST_1)
        s3_client.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        # Create Lambda Code
        zip_output = io.BytesIO()
        zip_file = zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED)
        zip_file.writestr(
            "lambda_function.py",
            """
            def lambda_handler(event, context):
                print("custom log event")
                return event
            """,
        )
        zip_file.close()
        zip_output.seek(0)
        # Create Rotation Lambda
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        resp = lambda_client.create_function(
            FunctionName="rotation-lambda",
            Runtime="python3.7",
            Role=iam_role,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_output.read()},
            Description="test lambda function",
            Timeout=3,
            MemorySize=128,
            PackageType="ZIP",
            Publish=True,
            VpcConfig={
                "SecurityGroupIds": ["sg-123abc"],
                "SubnetIds": ["subnet-123abc"],
            },
        )
        lambda_arn = resp["FunctionArn"]
        # Enable Rotation
        secretsmanager_client.rotate_secret(
            SecretId=secret_arn,
            RotationLambdaARN=lambda_arn,
            RotationRules={
                "AutomaticallyAfterDays": 90,
                "Duration": "3h",
                "ScheduleExpression": "rate(10 days)",
            },
            RotateImmediately=True,
        )

        # Set partition for the service
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        secretsmanager = SecretsManager(audit_info)

        assert len(secretsmanager.secrets) == 1
        assert secretsmanager.secrets
        assert secretsmanager.secrets[secret_arn]
        assert secretsmanager.secrets[secret_arn].name == secret_name
        assert secretsmanager.secrets[secret_arn].arn == secret_arn
        assert secretsmanager.secrets[secret_arn].region == AWS_REGION_EU_WEST_1
        assert secretsmanager.secrets[secret_arn].rotation_enabled is True
        assert secretsmanager.secrets[secret_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]
