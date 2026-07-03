from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_ami_account_block_public_access:
    @mock_aws
    def test_ec2_ami_block_public_access_state_unblocked(self):
        from prowler.providers.aws.services.ec2.ec2_service import AmiBlockPublicAccess

        ec2_client = mock.MagicMock()
        ec2_client.ami_block_public_access_states = [
            AmiBlockPublicAccess(status="unblocked", region=AWS_REGION_US_EAST_1)
        ]
        ec2_client.audited_account = AWS_ACCOUNT_NUMBER
        ec2_client.region = AWS_REGION_US_EAST_1
        ec2_client.account_arn_template = (
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_account_block_public_access.ec2_ami_account_block_public_access.ec2_client",
                new=ec2_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ami_account_block_public_access.ec2_ami_account_block_public_access import (
                ec2_ami_account_block_public_access,
            )

            check = ec2_ami_account_block_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AMI Block Public Access is disabled in {AWS_REGION_US_EAST_1}."
            )
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_ec2_ami_block_public_access_state_block_new_sharing(self):
        from prowler.providers.aws.services.ec2.ec2_service import AmiBlockPublicAccess

        ec2_client = mock.MagicMock()
        ec2_client.ami_block_public_access_states = [
            AmiBlockPublicAccess(
                status="block-new-sharing", region=AWS_REGION_US_EAST_1
            )
        ]
        ec2_client.audited_account = AWS_ACCOUNT_NUMBER
        ec2_client.region = AWS_REGION_US_EAST_1
        ec2_client.account_arn_template = (
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_account_block_public_access.ec2_ami_account_block_public_access.ec2_client",
                new=ec2_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ami_account_block_public_access.ec2_ami_account_block_public_access import (
                ec2_ami_account_block_public_access,
            )

            check = ec2_ami_account_block_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AMI Block Public Access is enabled in {AWS_REGION_US_EAST_1}."
            )
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
