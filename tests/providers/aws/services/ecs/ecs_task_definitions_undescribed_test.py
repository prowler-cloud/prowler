from datetime import datetime, timezone
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import botocore
import pytest

from prowler.providers.aws.services.ecs.ecs_service import ECS, TaskDefinition
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
make_api_call = botocore.client.BaseClient._make_api_call


def _mock_ecs_api(describe_result):
    def mock_make_api_call(self, operation_name, kwargs):
        if operation_name == "ListTaskDefinitions":
            return {"taskDefinitionArns": [TASK_ARN]}
        if operation_name == "DescribeTaskDefinition":
            if isinstance(describe_result, Exception):
                raise describe_result
            return describe_result
        if operation_name == "ListClusters":
            return {"clusterArns": []}
        return make_api_call(self, operation_name, kwargs)

    return mock_make_api_call


def _collect_task_definition(describe_result):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_ecs_api(describe_result),
    ):
        return ECS(aws_provider).task_definitions[TASK_ARN]


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


def test_failed_describe_leaves_task_definition_undescribed():
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "rate exceeded"}},
        "DescribeTaskDefinition",
    )

    task_definition = _collect_task_definition(error)

    assert task_definition.container_definitions is None
    assert task_definition.pid_mode is None
    assert task_definition.network_mode is None


def test_successful_describe_preserves_empty_container_definitions():
    task_definition = _collect_task_definition(
        {
            "taskDefinition": {
                "containerDefinitions": [],
                "pidMode": "task",
                "networkMode": "awsvpc",
            },
            "tags": [],
        }
    )

    assert task_definition.container_definitions == []
    assert task_definition.pid_mode == "task"
    assert task_definition.network_mode == "awsvpc"


def test_partial_parse_leaves_task_definition_undescribed():
    task_definition = _collect_task_definition(
        {
            "taskDefinition": {
                "containerDefinitions": [
                    {"name": "valid-container"},
                    {"privileged": False},
                ],
                "pidMode": "host",
                "networkMode": "host",
                "registeredAt": datetime(2026, 8, 13, tzinfo=timezone.utc),
            },
            "tags": [{"key": "Environment", "value": "production"}],
        }
    )

    assert task_definition.container_definitions is None
    assert task_definition.pid_mode is None
    assert task_definition.network_mode is None
    assert task_definition.registered_at is None
    assert task_definition.tags == []


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
