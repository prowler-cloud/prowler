from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    TaskDefinition,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
TASK_ARN = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{TASK_NAME}:{TASK_REVISION}"


class Test_ecs_task_definitions_logging_enabled:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_no_logconfiguration(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=TASK_ARN,
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    image="test-image",
                    privileged=False,
                    user="user-1",
                    environment=[{"name": "DB_PASSWORD", "value": "pass-12343"}],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers running with no logging configuration: {CONTAINER_NAME}"
            )

    def test_task_definition_no_logdriver(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=TASK_ARN,
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    privileged=True,
                    user="root",
                    environment=[],
                    log_driver="",
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers running with no logging configuration: {CONTAINER_NAME}"
            )

    def test_task_definition_privileged_container(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=TASK_ARN,
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    privileged=True,
                    user="root",
                    environment=[],
                    log_driver="awslogs",
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} containers have logging configured."
            )
