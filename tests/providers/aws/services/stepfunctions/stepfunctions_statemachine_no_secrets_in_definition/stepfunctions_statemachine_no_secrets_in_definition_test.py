from datetime import datetime
from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_stepfunctions_statemachine_no_secrets_in_definition:
    def test_no_statemachines(self):
        stepfunctions_client = mock.MagicMock()
        stepfunctions_client.state_machines = {}
        stepfunctions_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_service.StepFunctions",
                stepfunctions_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_client",
                stepfunctions_client,
            ),
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition import (
                stepfunctions_statemachine_no_secrets_in_definition,
            )

            check = stepfunctions_statemachine_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 0

    def test_statemachine_with_no_definition(self):
        stepfunctions_client = mock.MagicMock()

        from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
            StateMachine,
            StateMachineStatus,
            StateMachineType,
        )

        statemachine_arn = f"arn:aws:states:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stateMachine:TestStateMachine"
        stepfunctions_client.state_machines = {
            statemachine_arn: StateMachine(
                id="TestStateMachine",
                arn=statemachine_arn,
                name="TestStateMachine",
                status=StateMachineStatus.ACTIVE,
                definition=None,
                region=AWS_REGION_US_EAST_1,
                type=StateMachineType.STANDARD,
                creation_date=datetime.now(),
            )
        }
        stepfunctions_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_service.StepFunctions",
                stepfunctions_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_client",
                stepfunctions_client,
            ),
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition import (
                stepfunctions_statemachine_no_secrets_in_definition,
            )

            check = stepfunctions_statemachine_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in Step Functions state machine TestStateMachine definition."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "TestStateMachine"
            assert result[0].resource_arn == statemachine_arn

    def test_statemachine_with_no_secrets_in_definition(self):
        stepfunctions_client = mock.MagicMock()

        from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
            StateMachine,
            StateMachineStatus,
            StateMachineType,
        )

        statemachine_arn = f"arn:aws:states:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stateMachine:TestStateMachine"
        stepfunctions_client.state_machines = {
            statemachine_arn: StateMachine(
                id="TestStateMachine",
                arn=statemachine_arn,
                name="TestStateMachine",
                status=StateMachineStatus.ACTIVE,
                definition='{"Comment": "A simple example", "StartAt": "HelloWorld", "States": {"HelloWorld": {"Type": "Pass", "End": true}}}',
                region=AWS_REGION_US_EAST_1,
                type=StateMachineType.STANDARD,
                creation_date=datetime.now(),
            )
        }
        stepfunctions_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_service.StepFunctions",
                stepfunctions_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_client",
                stepfunctions_client,
            ),
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition import (
                stepfunctions_statemachine_no_secrets_in_definition,
            )

            check = stepfunctions_statemachine_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in Step Functions state machine TestStateMachine definition."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "TestStateMachine"
            assert result[0].resource_arn == statemachine_arn

    def test_statemachine_with_secrets_in_definition(self):
        stepfunctions_client = mock.MagicMock()

        from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
            StateMachine,
            StateMachineStatus,
            StateMachineType,
        )

        statemachine_arn = f"arn:aws:states:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:stateMachine:TestStateMachine"
        stepfunctions_client.state_machines = {
            statemachine_arn: StateMachine(
                id="TestStateMachine",
                arn=statemachine_arn,
                name="TestStateMachine",
                status=StateMachineStatus.ACTIVE,
                definition='{"Comment": "Example with secret", "StartAt": "MyTask", "States": {"MyTask": {"Type": "Task", "Parameters": {"api_key": "AKIAIOSFODNN7EXAMPLE"}, "End": true}}}',
                region=AWS_REGION_US_EAST_1,
                type=StateMachineType.STANDARD,
                creation_date=datetime.now(),
            )
        }
        stepfunctions_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_service.StepFunctions",
                stepfunctions_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_client",
                stepfunctions_client,
            ),
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_no_secrets_in_definition.stepfunctions_statemachine_no_secrets_in_definition import (
                stepfunctions_statemachine_no_secrets_in_definition,
            )

            check = stepfunctions_statemachine_no_secrets_in_definition()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "TestStateMachine" in result[0].status_extended
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "TestStateMachine"
            assert result[0].resource_arn == statemachine_arn
