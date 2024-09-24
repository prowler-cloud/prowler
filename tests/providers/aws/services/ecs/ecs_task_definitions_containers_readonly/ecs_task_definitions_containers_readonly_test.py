from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    TaskDefinition,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

task_name = "test-task-readonly"
task_revision = "1"
container_name = "test-container"
task_arn = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"


class Test_ecs_task_definitions_containers_readonly:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly.ecs_task_definitions_containers_readonly import (
                ecs_task_definitions_containers_readonly,
            )

            check = ecs_task_definitions_containers_readonly()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_all_containers_readonly(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {
            task_arn: TaskDefinition(
                name=task_name,
                arn=task_arn,
                revision=task_revision,
                region=AWS_REGION_US_EAST_1,
                network_mode="bridge",
                container_definitions=[
                    ContainerDefinition(
                        name=container_name,
                        readonly_rootfilesystem=True,
                        privileged=False,
                        user="appuser",
                        environment=[],
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly.ecs_task_definitions_containers_readonly import (
                ecs_task_definitions_containers_readonly,
            )

            check = ecs_task_definitions_containers_readonly()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {task_name} containers have read-only root filesystems."
            )

    def test_task_definition_some_containers_not_readonly(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {
            task_arn: TaskDefinition(
                name=task_name,
                arn=task_arn,
                revision=task_revision,
                region=AWS_REGION_US_EAST_1,
                network_mode="bridge",
                container_definitions=[
                    ContainerDefinition(
                        name=container_name,
                        readonly_rootfilesystem=False,
                        privileged=False,
                        user="appuser",
                        environment=[],
                    )
                ],
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly.ecs_task_definitions_containers_readonly import (
                ecs_task_definitions_containers_readonly,
            )

            check = ecs_task_definitions_containers_readonly()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' has containers with write access to the root filesystem: {container_name}"
            )

    def test_task_definition_mixed_containers(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {
            task_arn: TaskDefinition(
                name=task_name,
                arn=task_arn,
                revision=task_revision,
                region=AWS_REGION_US_EAST_1,
                network_mode="bridge",
                container_definitions=[
                    ContainerDefinition(
                        name=container_name,
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
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_client.ecs_client",
            new=ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly.ecs_task_definitions_containers_readonly import (
                ecs_task_definitions_containers_readonly,
            )

            check = ecs_task_definitions_containers_readonly()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' has containers with write access to the root filesystem: {container_name}"
            )
