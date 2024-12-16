from datetime import datetime
from unittest.mock import patch

import pytest
from moto import mock_aws

from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    LoggingConfiguration,
    LoggingLevel,
    StateMachine,
    StepFunctions,
)
from tests.providers.aws.utils import set_mocked_aws_provider

AWS_REGION_EU_WEST_1 = "eu-west-1"
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


@pytest.mark.parametrize(
    "state_machines, expected_status",
    [
        ({}, 0),  # No state machines
        (
            {
                STATE_MACHINE_ARN: create_state_machine(
                    "TestStateMachine",
                    create_logging_configuration(level=LoggingLevel.OFF),
                )
            },
            1,
        ),  # Logging disabled
        (
            {
                STATE_MACHINE_ARN: create_state_machine(
                    "TestStateMachine",
                    create_logging_configuration(
                        level=LoggingLevel.ALL,
                        include_execution_data=True,
                        destinations=[
                            "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vendedlogs/states"
                        ],
                    ),
                )
            },
            1,
        ),  # Logging enabled
    ],
)
@mock_aws(config={"stepfunctions": {"execute_state_machine": True}})
def test_stepfunctions_statemachine_logging(state_machines, expected_status):
    # Create a mocked AWS provider
    mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

    # Create StepFunctions client with mocked state machines
    stepfunctions_client = StepFunctions(mocked_aws_provider)
    stepfunctions_client.state_machines = state_machines

    # Patch the stepfunctions_client in the check module
    with patch(
        "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled.stepfunctions_client",
        new=stepfunctions_client,
    ):
        # Import the check dynamically
        from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_logging_enabled.stepfunctions_statemachine_logging_enabled import (
            stepfunctions_statemachine_logging_enabled,
        )

        # Execute the check
        check = stepfunctions_statemachine_logging_enabled()
        result = check.execute()

        # Assert the number of results and status
        assert len(result) == expected_status

        # Additional assertions for specific scenarios
        if expected_status == 1:
            if (
                state_machines[STATE_MACHINE_ARN].logging_configuration.level
                == LoggingLevel.OFF
            ):
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Step Functions state machine TestStateMachine does not have logging enabled."
                )
            else:
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Step Functions state machine TestStateMachine has logging enabled."
                )

            assert result[0].resource_id == STATE_MACHINE_ID
            assert result[0].resource_arn == STATE_MACHINE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
