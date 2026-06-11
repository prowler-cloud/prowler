from datetime import datetime
from unittest.mock import patch

import pytest
from moto import mock_aws

from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    EncryptionConfiguration,
    EncryptionType,
    StateMachine,
    StepFunctions,
)
from tests.providers.aws.utils import set_mocked_aws_provider

AWS_REGION_EU_WEST_1 = "eu-west-1"
STATE_MACHINE_ID = "state-machine-12345"
STATE_MACHINE_ARN = f"arn:aws:states:{AWS_REGION_EU_WEST_1}:123456789012:stateMachine:{STATE_MACHINE_ID}"
KMS_KEY_ARN = "arn:aws:kms:eu-west-1:123456789012:key/some-key-id"


def create_state_machine(name, encryption_configuration):
    """Create a mock StateMachine instance for use in tests.

    Args:
        name (str): The display name of the state machine.
        encryption_configuration (Optional[EncryptionConfiguration]): The encryption
            configuration to assign to the state machine, or None.

    Returns:
        StateMachine: A StateMachine instance pre-populated with test constants.
    """
    return StateMachine(
        id=STATE_MACHINE_ID,
        arn=STATE_MACHINE_ARN,
        name=name,
        region=AWS_REGION_EU_WEST_1,
        encryption_configuration=encryption_configuration,
        tags=[],
        status="ACTIVE",
        definition="{}",
        role_arn="arn:aws:iam::123456789012:role/step-functions-role",
        type="STANDARD",
        creation_date=datetime.now(),
    )


@pytest.mark.parametrize(
    "state_machines, expected_count, expected_status, expected_status_extended",
    [
        # No state machines , no findings
        ({}, 0, None, None),
        # AWS-owned key (default) , FAIL
        (
            {
                STATE_MACHINE_ARN: create_state_machine(
                    "TestStateMachine",
                    EncryptionConfiguration(
                        type=EncryptionType.AWS_OWNED_KEY,
                        kms_key_id=None,
                        kms_data_key_reuse_period_seconds=None,
                    ),
                )
            },
            1,
            "FAIL",
            "Step Functions state machine TestStateMachine is not encrypted at rest with a customer-managed KMS key.",
        ),
        # No encryption configuration (None) , FAIL
        (
            {
                STATE_MACHINE_ARN: create_state_machine(
                    "TestStateMachine",
                    None,
                )
            },
            1,
            "FAIL",
            "Step Functions state machine TestStateMachine is not encrypted at rest with a customer-managed KMS key.",
        ),
        # Customer-managed KMS key , PASS
        (
            {
                STATE_MACHINE_ARN: create_state_machine(
                    "TestStateMachine",
                    EncryptionConfiguration(
                        type=EncryptionType.CUSTOMER_MANAGED_KMS_KEY,
                        kms_key_id=KMS_KEY_ARN,
                        kms_data_key_reuse_period_seconds=300,
                    ),
                )
            },
            1,
            "PASS",
            "Step Functions state machine TestStateMachine is encrypted at rest with a customer-managed KMS key.",
        ),
    ],
)
@mock_aws(config={"stepfunctions": {"execute_state_machine": True}})
def test_stepfunctions_statemachine_encryption_at_rest(
    state_machines,
    expected_count,
    expected_status,
    expected_status_extended,
):
    """Test stepfunctions_statemachine_encryption_at_rest_enabled check across multiple scenarios.

    Parametrized test cases cover:
    - No state machines present (empty findings).
    - State machine using the default AWS-owned key (FAIL).
    - State machine with no encryption configuration set (FAIL).
    - State machine using a customer-managed KMS key (PASS).

    Args:
        state_machines (dict): Mapping of ARN to StateMachine used to mock the service client.
        expected_count (int): Expected number of findings returned by the check.
        expected_status (Optional[str]): Expected status of the finding, or None if no findings.
        expected_status_extended (Optional[str]): Expected status_extended message, or None.
    """
    mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
    stepfunctions_client = StepFunctions(mocked_aws_provider)
    stepfunctions_client.state_machines = state_machines

    with patch(
        "prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_encryption_at_rest_enabled.stepfunctions_statemachine_encryption_at_rest_enabled.stepfunctions_client",
        new=stepfunctions_client,
    ):
        from prowler.providers.aws.services.stepfunctions.stepfunctions_statemachine_encryption_at_rest_enabled.stepfunctions_statemachine_encryption_at_rest_enabled import (
            stepfunctions_statemachine_encryption_at_rest_enabled,
        )

        check = stepfunctions_statemachine_encryption_at_rest_enabled()
        result = check.execute()

        assert len(result) == expected_count

        if expected_count == 1:
            assert result[0].status == expected_status
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource_id == STATE_MACHINE_ID
            assert result[0].resource_arn == STATE_MACHINE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource == state_machines[STATE_MACHINE_ARN]
