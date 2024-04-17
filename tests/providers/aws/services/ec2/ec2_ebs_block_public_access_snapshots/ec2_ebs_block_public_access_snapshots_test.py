from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock__get_snapshot_block_public_access_state__(status):
    return [
        mock.MagicMock(region=AWS_REGION_US_EAST_1, status=status),
    ]


class Test_ec2_ebs_block_public_access_snapshots:
    @mock_aws
    def test_ec2_ebs_block_public_access_state_unblocked(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_block_public_access_snapshots.ec2_ebs_block_public_access_snapshots.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_block_public_access_snapshots.ec2_ebs_block_public_access_snapshots import (
                ec2_ebs_block_public_access_snapshots,
            )

            check = ec2_ebs_block_public_access_snapshots()
            results = check.execute()

            # One result per region
            assert len(results) == 2
            for result in results:
                if result.region == AWS_REGION_US_EAST_1:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == "EBS Default Encryption is not activated."
                    )
                    assert result.resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        result.resource_arn
                        == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume"
                    )
                if result.region == AWS_REGION_EU_WEST_1:
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == "EBS Default Encryption is not activated."
                    )
                    assert result.resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        result.resource_arn
                        == f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume"
                    )
