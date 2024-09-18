from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    ContainerEnvVariable,
    TaskDefinition,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

task_name = "test-task"
task_revision = "1"
container_name = "test-container"
task_arn = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"


class Test_ecs_task_definitions_host_networking_mode_users:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
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
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=task_arn,
            revision=task_revision,
            region=AWS_REGION_US_EAST_1,
            network_mode="bridge",
            container_definitions=[
                ContainerDefinition(
                    name=container_name,
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
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
                == f"ECS task definition '{task_name}' does not have host network mode."
            )

    def test_task_definition_host_mode_container_root_non_privileged(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=task_arn,
            revision=task_revision,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=container_name,
                    privileged=False,
                    user="root",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
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
                == f"ECS task definition '{task_name}' has containers with host network mode and non-privileged containers running as root or with no user specified: {container_name}"
            )

    def test_task_definition_host_mode_container_privileged(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
            revision=task_revision,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=container_name,
                    privileged=True,
                    user="root",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
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
                == f"ECS task definition '{task_name}' has host network mode but no containers running as root or with no user specified."
            )

    def test_task_definition_host_mode_container_not_root(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=task_arn,
            revision=task_revision,
            region=AWS_REGION_US_EAST_1,
            network_mode="host",
            container_definitions=[
                ContainerDefinition(
                    name=container_name,
                    privileged=False,
                    user="appuser",
                    environment=[],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
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
                == f"ECS task definition '{task_name}' has host network mode but no containers running as root or with no user specified."
            )
