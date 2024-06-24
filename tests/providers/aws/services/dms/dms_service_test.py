import botocore
from mock import patch

from prowler.providers.aws.services.dms.dms_service import DMS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DMS_INSTANCE_NAME = "rep-instance"
DMS_INSTANCE_ARN = (
    f"arn:aws:dms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rep:{DMS_INSTANCE_NAME}"
)
KMS_KEY_ID = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/abcdabcd-1234-abcd-1234-abcdabcdabcd"

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
