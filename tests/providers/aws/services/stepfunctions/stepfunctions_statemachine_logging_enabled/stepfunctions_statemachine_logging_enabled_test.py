from datetime import datetime
from unittest.mock import patch

from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    LoggingConfiguration,
    LoggingLevel,
    StateMachine,
    StepFunctions,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

STATE_MACHINE_ID = "state-machine-12345"
STATE_MACHINE_ARN = f"arn:aws:states:{AWS_REGION_EU_WEST_1}:123456789012:stateMachine:{STATE_MACHINE_ID}"


def create_logging_configuration(
    level, include_execution_data=False, destinations=None
):
    return LoggingConfiguration(
        level=level,
        include_execution_data=include_execution_data,
        destinations=[
            {"cloud_watch_logs_log_group": {"log_group_arn": dest}}
            for dest in (destinations or [])
        ],
    )


def create_state_machine(name, logging_configuration):
    return StateMachine(
        id=STATE_MACHINE_ID,
        arn=STATE_MACHINE_ARN,
        name=name,
        region=AWS_REGION_EU_WEST_1,
        logging_configuration=logging_configuration,
        tags=[],
        status="ACTIVE",
        definition="{}",
        role_arn="arn:aws:iam::123456789012:role/step-functions-role",
        type="STANDARD",
        creation_date=datetime.now(),
    )


class Test_stepfunctions_statemachine_logging_enabled:
    def test_no_state_machines(self):
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        stepfunctions_client = StepFunctions(mocked_aws_provider)
        stepfunctions_client.state_machines = {}

        with patch(
            "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled.stepfunctions_client",
            new=stepfunctions_client,
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled import (
                stepfunctions_statemachine_logging_enabled,
            )

            check = stepfunctions_statemachine_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_state_machine_logging_disabled(self):
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        stepfunctions_client = StepFunctions(mocked_aws_provider)
        stepfunctions_client.state_machines[STATE_MACHINE_ARN] = create_state_machine(
            "TestStateMachine", create_logging_configuration(level=LoggingLevel.OFF)
        )

        with patch(
            "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled.stepfunctions_client",
            new=stepfunctions_client,
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled import (
                stepfunctions_statemachine_logging_enabled,
            )

            check = stepfunctions_statemachine_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Step Functions state machine TestStateMachine does not have logging enabled."
            )
            assert result[0].resource_id == STATE_MACHINE_ID
            assert result[0].resource_arn == STATE_MACHINE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_state_machine_logging_enabled(self):
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        stepfunctions_client = StepFunctions(mocked_aws_provider)
        stepfunctions_client.state_machines[STATE_MACHINE_ARN] = create_state_machine(
            "TestStateMachine",
            create_logging_configuration(
                level=LoggingLevel.ALL,
                include_execution_data=True,
                destinations=[
                    "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vendedlogs/states"
                ],
            ),
        )

        with patch(
            "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled.stepfunctions_client",
            new=stepfunctions_client,
        ):
            from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled import (
                stepfunctions_statemachine_logging_enabled,
            )

            check = stepfunctions_statemachine_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Step Functions state machine TestStateMachine has logging enabled."
            )
            assert result[0].resource_id == STATE_MACHINE_ID
            assert result[0].resource_arn == STATE_MACHINE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
