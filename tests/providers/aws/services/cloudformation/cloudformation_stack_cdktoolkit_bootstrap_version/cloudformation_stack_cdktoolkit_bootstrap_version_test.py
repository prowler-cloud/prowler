from unittest import mock

from prowler.providers.aws.services.cloudformation.cloudformation_service import Stack

# Mock Test Region
AWS_REGION = "eu-west-1"


class Test_cloudformation_stack_cdktoolkit_bootstrap_version:
    def test_no_stacks(self):
        cloudformation_client = mock.MagicMock
        cloudformation_client.stacks = []
        cloudformation_client.audit_config = {"recommended_cdk_bootstrap_version": 21}
        with (
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
                new=cloudformation_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_client.cloudformation_client",
                new=cloudformation_client,
            ),
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_cdktoolkit_bootstrap_version.cloudformation_stack_cdktoolkit_bootstrap_version import (
                cloudformation_stack_cdktoolkit_bootstrap_version,
            )

            check = cloudformation_stack_cdktoolkit_bootstrap_version()
            result = check.execute()

            assert len(result) == 0

    def test_stack_with_valid_bootstrap_version(self):
        cloudformation_client = mock.MagicMock
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/CDKToolkit/1234abcd",
                name="CDKToolkit",
                outputs=["BootstrapVersion:21"],
                region=AWS_REGION,
            )
        ]
        cloudformation_client.audit_config = {"recommended_cdk_bootstrap_version": 21}

        with (
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
                new=cloudformation_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_client.cloudformation_client",
                new=cloudformation_client,
            ),
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_cdktoolkit_bootstrap_version.cloudformation_stack_cdktoolkit_bootstrap_version import (
                cloudformation_stack_cdktoolkit_bootstrap_version,
            )

            check = cloudformation_stack_cdktoolkit_bootstrap_version()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudFormation Stack CDKToolkit has a Bootstrap version 21, which meets the recommended version."
            )
            assert result[0].resource_id == "CDKToolkit"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/CDKToolkit/1234abcd"
            )
            assert result[0].region == AWS_REGION

    def test_stack_with_invalid_bootstrap_version(self):
        cloudformation_client = mock.MagicMock
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/CDKToolkit/1234abcd",
                name="CDKToolkit",
                outputs=["BootstrapVersion:20"],
                region=AWS_REGION,
            )
        ]
        cloudformation_client.audit_config = {"recommended_cdk_bootstrap_version": 21}

        with (
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
                new=cloudformation_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudformation.cloudformation_client.cloudformation_client",
                new=cloudformation_client,
            ),
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_cdktoolkit_bootstrap_version.cloudformation_stack_cdktoolkit_bootstrap_version import (
                cloudformation_stack_cdktoolkit_bootstrap_version,
            )

            check = cloudformation_stack_cdktoolkit_bootstrap_version()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CloudFormation Stack CDKToolkit has a Bootstrap version 20, which is less than the recommended version 21."
            )
            assert result[0].resource_id == "CDKToolkit"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/CDKToolkit/1234abcd"
            )
            assert result[0].region == AWS_REGION
