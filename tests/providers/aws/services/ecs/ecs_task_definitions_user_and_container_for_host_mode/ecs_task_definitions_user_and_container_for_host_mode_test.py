from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    ContainerEnvVariable,
    TaskDefinition,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
task_name = "test-task"
task_revision = "1"
container_name = "test-container"
task_arn = f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"


class Test_ecs_task_definitions_user_and_container_for_host_mode:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_user_and_container_for_host_mode.ecs_task_definitions_user_and_container_for_host_mode import (
                ecs_task_definitions_user_and_container_for_host_mode,
            )

            check = ecs_task_definitions_user_and_container_for_host_mode()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_no_host_network_mode(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=task_arn,
            revision="1",
            region=AWS_REGION,
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
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_user_and_container_for_host_mode.ecs_task_definitions_user_and_container_for_host_mode import (
                ecs_task_definitions_user_and_container_for_host_mode,
            )

            check = ecs_task_definitions_user_and_container_for_host_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' does not have host network mode."
            )

    def test_task_definition_host_mode_container_root_non_privileged(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=task_arn,
            revision="1",
            region=AWS_REGION,
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
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_user_and_container_for_host_mode.ecs_task_definitions_user_and_container_for_host_mode import (
                ecs_task_definitions_user_and_container_for_host_mode,
            )

            check = ecs_task_definitions_user_and_container_for_host_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' with host network mode has issues: Container '{container_name}' is running as root user but is not privileged."
            )

    def test_task_definition_host_mode_container_privileged(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = [
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
                revision="1",
                region=AWS_REGION,
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
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_user_and_container_for_host_mode.ecs_task_definitions_user_and_container_for_host_mode import (
                ecs_task_definitions_user_and_container_for_host_mode,
            )

            check = ecs_task_definitions_user_and_container_for_host_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' with host network mode has no issues with container definitions."
            )

    def test_task_definition_host_mode_container_not_root(self):
        ecs_client = mock.MagicMock()
        ecs_client.task_definitions = [
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
                revision="1",
                region=AWS_REGION,
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
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            ),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_user_and_container_for_host_mode.ecs_task_definitions_user_and_container_for_host_mode import (
                ecs_task_definitions_user_and_container_for_host_mode,
            )

            check = ecs_task_definitions_user_and_container_for_host_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition '{task_name}' with host network mode has no issues with container definitions."
            )
