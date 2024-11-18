import botocore
from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.dms.dms_service import DMS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DMS_INSTANCE_NAME = "rep-instance"
DMS_INSTANCE_ARN = (
    f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rep:{DMS_INSTANCE_NAME}"
)
KMS_KEY_ID = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/abcdabcd-1234-abcd-1234-abcdabcdabcd"

DMS_ENDPOINT_NAME = "dms-endpoint"
DMS_ENDPOINT_ARN = f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:endpoint:{DMS_ENDPOINT_NAME}"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    if operation_name == "DescribeReplicationInstances":
        return {
            "ReplicationInstances": [
                {
                    "ReplicationInstanceIdentifier": DMS_INSTANCE_NAME,
                    "ReplicationInstanceStatus": "available",
                    "AutoMinorVersionUpgrade": True,
                    "PubliclyAccessible": True,
                    "ReplicationInstanceArn": DMS_INSTANCE_ARN,
                    "MultiAZ": True,
                    "VpcSecurityGroups": [],
                    "KmsKeyId": KMS_KEY_ID,
                },
            ]
        }
    elif operation_name == "DescribeEndpoints":
        return {
            "Endpoints": [
                {
                    "EndpointIdentifier": DMS_ENDPOINT_NAME,
                    "EndpointArn": DMS_ENDPOINT_ARN,
                    "SslMode": "require",
                    "RedisSettings": {
                        "SslSecurityProtocol": "ssl-encryption",
                    },
                    "MongoDbSettings": {
                        "AuthType": "password",
                    },
                    "NeptuneSettings": {
                        "IamAuthEnabled": True,
                    },
                    "EngineName": "neptune",
                }
            ]
        }
    elif operation_name == "ListTagsForResource":
        if kwargs["ResourceArn"] == DMS_INSTANCE_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "rep-instance"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }
        elif kwargs["ResourceArn"] == DMS_ENDPOINT_ARN:
            return {
                "TagList": [
                    {"Key": "Name", "Value": "dms-endpoint"},
                    {"Key": "Owner", "Value": "admin"},
                ]
            }

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DMS_Service:
    # Test DMS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        DMS(aws_provider)

    # Test DMS Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        dms = DMS(aws_provider)
        assert dms.client.__class__.__name__ == "DatabaseMigrationService"

    # Test DMS Account
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        dms = DMS(aws_provider)
        assert dms.audited_account == AWS_ACCOUNT_NUMBER

    # Test DMS Replication Instances
    def test_describe_rep_instances(self):
        aws_provider = set_mocked_aws_provider()
        dms = DMS(aws_provider)

        assert len(dms.instances) == 1
        assert dms.instances[0].id == DMS_INSTANCE_NAME
        assert dms.instances[0].region == AWS_REGION_US_EAST_1
        assert dms.instances[0].status == "available"
        assert dms.instances[0].public
        assert dms.instances[0].kms_key == KMS_KEY_ID
        assert dms.instances[0].auto_minor_version_upgrade
        assert dms.instances[0].multi_az
        assert dms.instances[0].security_groups == []

    # Test DMS Endpoints
    def test_describe_endpoints(self):
        aws_provider = set_mocked_aws_provider()
        dms = DMS(aws_provider)

        assert len(dms.endpoints) == 1
        assert dms.endpoints[DMS_ENDPOINT_ARN].id == DMS_ENDPOINT_NAME
        assert dms.endpoints[DMS_ENDPOINT_ARN].ssl_mode == "require"
        assert dms.endpoints[DMS_ENDPOINT_ARN].redis_ssl_protocol == "ssl-encryption"
        assert dms.endpoints[DMS_ENDPOINT_ARN].mongodb_auth_type == "password"
        assert dms.endpoints[DMS_ENDPOINT_ARN].neptune_iam_auth_enabled
        assert dms.endpoints[DMS_ENDPOINT_ARN].engine_name == "neptune"

    def test_list_tags(self):
        aws_provider = set_mocked_aws_provider()
        dms = DMS(aws_provider)

        assert dms.instances[0].tags == [
            {"Key": "Name", "Value": "rep-instance"},
            {"Key": "Owner", "Value": "admin"},
        ]
        assert dms.endpoints[DMS_ENDPOINT_ARN].tags == [
            {"Key": "Name", "Value": "dms-endpoint"},
            {"Key": "Owner", "Value": "admin"},
        ]

    @mock_aws
    def test_describe_replication_tags(self):
        dms_client = client("dms", region_name=AWS_REGION_US_EAST_1)

        dms_client.create_replication_task(
            ReplicationTaskIdentifier="rep-task",
            SourceEndpointArn=DMS_ENDPOINT_ARN,
            TargetEndpointArn=DMS_ENDPOINT_ARN,
            MigrationType="full-load",
            ReplicationTaskSettings="""
                {
                    "Logging": {
                        "EnableLogging": true,
                        "LogComponents": [
                            {
                                "Id": "SOURCE_CAPTURE",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            },
                            {
                                "Id": "SOURCE_UNLOAD",
                                "Severity": "LOGGER_SEVERITY_DEFAULT"
                            }
                        ]
                    }
                }
            """,
            TableMappings="",
            ReplicationInstanceArn=DMS_INSTANCE_ARN,
        )

        dms_replication_task_arn = dms_client.describe_replication_tasks()[
            "ReplicationTasks"
        ][0]["ReplicationTaskArn"]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        dms = DMS(aws_provider)

        assert dms.replication_tasks[dms_replication_task_arn].id == "rep-task"
        assert (
            dms.replication_tasks[dms_replication_task_arn].region
            == AWS_REGION_US_EAST_1
        )
        assert dms.replication_tasks[dms_replication_task_arn].logging_enabled
        assert dms.replication_tasks[dms_replication_task_arn].log_components == [
            {"Id": "SOURCE_CAPTURE", "Severity": "LOGGER_SEVERITY_DEFAULT"},
            {"Id": "SOURCE_UNLOAD", "Severity": "LOGGER_SEVERITY_DEFAULT"},
        ]
        assert (
            dms.replication_tasks[dms_replication_task_arn].source_endpoint_arn
            == DMS_ENDPOINT_ARN
        )
        assert (
            dms.replication_tasks[dms_replication_task_arn].target_endpoint_arn
            == DMS_ENDPOINT_ARN
        )
