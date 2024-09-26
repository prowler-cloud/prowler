from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    ContainerEnvVariable,
    TaskDefinition,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

TASK_NAME = "test-task-hostmode"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
TASK_ARN = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{TASK_NAME}:{TASK_REVISION}"


class Test_ecs_task_definitions_host_networking_mode_users:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_no_host_network_mode(self):
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
                    privileged=False,
                    user="",
                    environment=[
                        ContainerEnvVariable(
                            name="env_var_name_no_secrets",
                            value="env_var_value_no_secrets",
                        )
                    ],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{TASK_NAME}' does not have host network mode."
            )

    def test_task_definition_host_mode_container_root_non_privileged(self):
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
                    privileged=False,
                    user="root",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition '{TASK_NAME}' has containers with host network mode and non-privileged containers running as root or with no user specified: {CONTAINER_NAME}"
            )

    def test_task_definition_host_mode_container_privileged(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[TASK_ARN] = TaskDefinition(
            name=TASK_NAME,
            arn=f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{TASK_NAME}:{TASK_REVISION}",
            revision=TASK_REVISION,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=CONTAINER_NAME,
                    privileged=True,
                    user="root",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{TASK_NAME}' has host network mode but no containers running as root or with no user specified."
            )

    def test_task_definition_host_mode_container_not_root(self):
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
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{TASK_NAME}' has host network mode but no containers running as root or with no user specified."
            )
