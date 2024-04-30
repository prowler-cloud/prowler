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


def mock_modify_instance_metadata_defaults(HttpTokens):
    if HttpTokens == "required":
        return {"Return": True}


class Test_ec2_instance_account_imdsv2_enabled_fixer:
    @mock_aws
    def test_ec2_instance_account_imdsv2_enabled_fixer(self):
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

        ec2_client.modify_instance_metadata_defaults = (
            mock_modify_instance_metadata_defaults
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled_fixer.ec2_client",
            ec2_service,
        ):

            from prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled_fixer import (
                fixer,
            )

            # By default, the account has not public access blocked
            assert fixer(region=AWS_REGION_US_EAST_1)
