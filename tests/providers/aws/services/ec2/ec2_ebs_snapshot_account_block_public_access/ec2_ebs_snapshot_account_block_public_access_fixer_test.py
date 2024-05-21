from unittest import mock

from moto import mock_aws

from prowler.providers.aws.services.ec2.ec2_service import (
    EbsSnapshotBlockPublicAccess,
    InstanceMetadataDefaults,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


# Since moto does not support the ec2 metadata service, we need to mock the response for some functions
def mock_get_instance_metadata_defaults(http_tokens, instances, region):
    return InstanceMetadataDefaults(
        http_tokens=http_tokens, instances=instances, region=region
    )


def mock_get_snapshot_block_public_access_state(status, snapshots, region):
    return EbsSnapshotBlockPublicAccess(
        status=status, snapshots=snapshots, region=region
    )


def mock_enable_snapshot_block_public_access(State):
    return {"State": State}


class Test_ec2_ebs_snapshot_account_block_public_access_fixer:
    @mock_aws
    def test_ec2_ebs_snapshot_account_block_public_access_fixer(self):
        ec2_service = mock.MagicMock()
        ec2_client = mock.MagicMock()
        ec2_service.regional_clients = {AWS_REGION_US_EAST_1: ec2_client}

        ec2_client.instance_metadata_defaults = [
            mock_get_instance_metadata_defaults(
                http_tokens="required", instances=True, region=AWS_REGION_US_EAST_1
            )
        ]

        ec2_client.ebs_block_public_access_snapshots_states = [
            mock_get_snapshot_block_public_access_state(
                status="block-all-sharing", snapshots=True, region=AWS_REGION_US_EAST_1
            )
        ]

        ec2_client.enable_snapshot_block_public_access = (
            mock_enable_snapshot_block_public_access
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_snapshot_account_block_public_access.ec2_ebs_snapshot_account_block_public_access_fixer.ec2_client",
            ec2_service,
        ):

            from prowler.providers.aws.services.ec2.ec2_ebs_snapshot_account_block_public_access.ec2_ebs_snapshot_account_block_public_access_fixer import (
                fixer,
            )

            # By default, the account has not public access blocked
            assert fixer(region=AWS_REGION_US_EAST_1)
