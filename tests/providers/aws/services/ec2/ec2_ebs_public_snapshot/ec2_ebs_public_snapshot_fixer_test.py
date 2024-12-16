from unittest import mock

import botocore
import botocore.client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_public_snapshot(self, operation_name, kwarg):
    if operation_name == "ModifySnapshotAttribute":
        return {
            "SnapshotId": "testsnap",
            "Attribute": "createVolumePermission",
            "OperationType": "remove",
            "GroupNames": ["all"],
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_error(self, operation_name, kwarg):
    if operation_name == "ModifySnapshotAttribute":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "UnauthorizedOperation",
                    "Message": "You are not authorized to perform this operation.",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_ec2_ebs_public_snapshot_fixer_test:
    @mock_aws
    def test_ebs_public_snapshot(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_snapshot,
        ):

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            )

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot_fixer.ec2_client",
                new=EC2(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot_fixer import (
                    fixer,
                )

                assert fixer("testsnap", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_ebs_public_snapshot_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_error
        ):

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            )

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot_fixer.ec2_client",
                new=EC2(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot_fixer import (
                    fixer,
                )

                assert not fixer("testsnap", AWS_REGION_US_EAST_1)
