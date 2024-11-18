from unittest import mock

from prowler.providers.aws.services.cloudformation.cloudformation_service import Stack

# Mock Test Region
AWS_REGION = "eu-west-1"


class Test_cloudformation_stack_outputs_find_secrets:
    def test_no_stacks(self):
        cloudformation_client = mock.MagicMock
        cloudformation_client.stacks = []
        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            new=cloudformation_client,
        ):
            # Test Check
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_outputs_find_secrets.cloudformation_stack_outputs_find_secrets import (
                cloudformation_stack_outputs_find_secrets,
            )

            check = cloudformation_stack_outputs_find_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_stack_secret_in_outputs(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=["DB_PASSWORD:foobar123", "ENV:DEV"],
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_outputs_find_secrets.cloudformation_stack_outputs_find_secrets import (
                cloudformation_stack_outputs_find_secrets,
            )

            check = cloudformation_stack_outputs_find_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Stack {stack_name} Outputs -> Secret Keyword in Output 1."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_stack_secret_in_outputs_false_case(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=[
                    "LocalSecurityTopic:arn:aws:sns:eu-west-1:123456789012:LocalSecurityTopic"
                ],
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_outputs_find_secrets.cloudformation_stack_outputs_find_secrets import (
                cloudformation_stack_outputs_find_secrets,
            )

            check = cloudformation_stack_outputs_find_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Stack {stack_name} Outputs."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_stack_no_secret_in_outputs(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=["ENV:DEV"],
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_outputs_find_secrets.cloudformation_stack_outputs_find_secrets import (
                cloudformation_stack_outputs_find_secrets,
            )

            check = cloudformation_stack_outputs_find_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Stack {stack_name} Outputs."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_stack_no_outputs(self):
        cloudformation_client = mock.MagicMock
        stack_name = "Test-Stack"
        cloudformation_client.stacks = [
            Stack(
                arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60",
                name=stack_name,
                outputs=[],
                region=AWS_REGION,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.cloudformation.cloudformation_service.CloudFormation",
            cloudformation_client,
        ):
            from prowler.providers.aws.services.cloudformation.cloudformation_stack_outputs_find_secrets.cloudformation_stack_outputs_find_secrets import (
                cloudformation_stack_outputs_find_secrets,
            )

            check = cloudformation_stack_outputs_find_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CloudFormation {stack_name} has no Outputs."
            )
            assert result[0].resource_id == "Test-Stack"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudformation:eu-west-1:123456789012:stack/Test-Stack/796c8d26-b390-41d7-a23c-0702c4e78b60"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
