from unittest import mock

from prowler.providers.aws.services.cloudformation.cloudformation_service import Stack
from tests.providers.aws.audit_info_utils import AWS_REGION_EU_WEST_1


class Test_cloudformation_stacks_termination_protection_enabled:
    def test_no_stacks(self):
        cloudformation_client = mock.MagicMock
        cloudformation_client.stacks = []
        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            new=cloudformation_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudformation.cloudformation_stacks_termination_protection_enabled.cloudformation_stacks_termination_protection_enabled import (
                cloudformation_stacks_termination_protection_enabled,
            )

            check = cloudformation_stacks_termination_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_stack_termination_protection_enabled(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=[],
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        cloudformation_client.stacks[0].enable_termination_protection = True

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stacks_termination_protection_enabled.cloudformation_stacks_termination_protection_enabled import (
                cloudformation_stacks_termination_protection_enabled,
            )

            check = cloudformation_stacks_termination_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFormation {stack_name} has termination protection enabled."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_stack_termination_protection_disabled(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=[],
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        cloudformation_client.stacks[0].enable_termination_protection = False

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stacks_termination_protection_enabled.cloudformation_stacks_termination_protection_enabled import (
                cloudformation_stacks_termination_protection_enabled,
            )

            check = cloudformation_stacks_termination_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CloudFormation {stack_name} has termination protection disabled."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
