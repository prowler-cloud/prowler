from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    TaskDefinition,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

TASK_NAME = "test-task-readonly"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
TASK_ARN = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{TASK_NAME}:{TASK_REVISION}"


class Test_ecs_task_definitions_containers_readonly_access:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_all_containers_readonly(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=TASK_ARN,
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="bridge",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    readonly_rootfilesystem=True,
                    privileged=False,
                    user="appuser",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} does not have containers with write access to the root filesystems."
            )

    def test_task_definition_some_containers_not_readonly(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=TASK_ARN,
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="bridge",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    readonly_rootfilesystem=False,
                    privileged=False,
                    user="appuser",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with write access to the root filesystem: {CONTAINER_NAME}"
            )

    def test_task_definition_mixed_containers(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {
            TASK_ARN: TaskDefinition(
                name=TASK_NAME,
                arn=TASK_ARN,
                revision=TASK_REVISION,
                region=AWS_REGION_US_EAST_1,
                network_mode="bridge",
                container_definitions=[
                    ContainerDefinition(
                        name=CONTAINER_NAME,
                        readonly_rootfilesystem=False,
                        privileged=False,
                        user="appuser",
                        environment=[],
                    ),
                    ContainerDefinition(
                        name="readonly-container",
                        readonly_rootfilesystem=True,
                        privileged=False,
                        user="appuser",
                        environment=[],
                    ),
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with write access to the root filesystem: {CONTAINER_NAME}"
            )
