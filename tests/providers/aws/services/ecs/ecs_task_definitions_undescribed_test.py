from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from prowler.providers.aws.services.ecs.ecs_service import TaskDefinition
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

TASK_NAME = "test-task"
TASK_REVISION = "1"
TASK_ARN = (
    f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
    f"task-definition/{TASK_NAME}:{TASK_REVISION}"
)


def _undescribed_ecs_client():
    task_definition = TaskDefinition(
        name=TASK_NAME,
        arn=TASK_ARN,
        revision=TASK_REVISION,
        region=AWS_REGION_US_EAST_1,
        environment_variables=[],
    )
    task_definition.container_definitions = None
    return SimpleNamespace(
        audit_config={},
        task_definitions={TASK_ARN: task_definition},
    )


@pytest.mark.parametrize(
    ("check_package", "check_name"),
    [
        (
            "ecs_task_definitions_containers_readonly_access",
            "ecs_task_definitions_containers_readonly_access",
        ),
        (
            "ecs_task_definitions_host_namespace_not_shared",
            "ecs_task_definitions_host_namespace_not_shared",
        ),
        (
            "ecs_task_definitions_host_networking_mode_users",
            "ecs_task_definitions_host_networking_mode_users",
        ),
        (
            "ecs_task_definitions_logging_block_mode",
            "ecs_task_definitions_logging_block_mode",
        ),
        (
            "ecs_task_definitions_logging_enabled",
            "ecs_task_definitions_logging_enabled",
        ),
        (
            "ecs_task_definitions_no_environment_secrets",
            "ecs_task_definitions_no_environment_secrets",
        ),
        (
            "ecs_task_definitions_no_privileged_containers",
            "ecs_task_definitions_no_privileged_containers",
        ),
    ],
)
def test_undescribed_task_definitions_are_not_reported(
    check_package, check_name, monkeypatch
):
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
    ):
        module = import_module(
            f"prowler.providers.aws.services.ecs.{check_package}.{check_name}"
        )
    monkeypatch.setattr(module, "ecs_client", _undescribed_ecs_client())

    check = getattr(module, check_name)()

    assert check.execute() == []
