from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_instance_account_imdsv2_enabled:
    @mock_aws
    def test_ec2_imdsv2_required(self):
        from prowler.providers.aws.services.ec2.ec2_service import (
            InstanceMetadataDefaults,
        )

        ec2_client = mock.MagicMock()
        ec2_client.instance_metadata_defaults = [
            InstanceMetadataDefaults(
                http_tokens="required", instances=True, region=AWS_REGION_US_EAST_1
            )
        ]
        ec2_client.audited_account = AWS_ACCOUNT_NUMBER
        ec2_client.region = AWS_REGION_US_EAST_1
        ec2_client.account_arn_template = (
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled.ec2_client",
            new=ec2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled import (
                ec2_instance_account_imdsv2_enabled,
            )

            check = ec2_instance_account_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IMDSv2 is enabled by default for EC2 instances."
            )
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_ec2_imdsv2_none(self):
        from prowler.providers.aws.services.ec2.ec2_service import (
            InstanceMetadataDefaults,
        )

        ec2_client = mock.MagicMock()
        ec2_client.instance_metadata_defaults = [
            InstanceMetadataDefaults(
                http_tokens=None, instances=True, region=AWS_REGION_US_EAST_1
            )
        ]
        ec2_client.audited_account = AWS_ACCOUNT_NUMBER
        ec2_client.region = AWS_REGION_US_EAST_1

        ec2_client.account_arn_template = (
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled.ec2_client",
            new=ec2_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_account_imdsv2_enabled.ec2_instance_account_imdsv2_enabled import (
                ec2_instance_account_imdsv2_enabled,
            )

            check = ec2_instance_account_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IMDSv2 is not enabled by default for EC2 instances."
            )
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
