from re import search
from unittest import mock

from providers.aws.services.ecs.ecs_service import ContainerEnvVariable, TaskDefinition

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
task_name = "test-task"
env_var_name_no_secrets = "host"
env_var_value_no_secrets = "localhost:1234"
env_var_name_with_secrets = "DB_PASSWORD"
env_var_value_with_secrets = "pass-12343"


class Test_ecs_task_definitions_no_environment_secrets:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []

        with mock.patch(
            "providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 0

    def test_container_env_var_no_secrets(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []
        ecs_client.task_definitions.append(
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:1",
                region=AWS_REGION,
                environment_variables=[
                    ContainerEnvVariable(
                        name=env_var_name_no_secrets, value=env_var_value_no_secrets
                    )
                ],
            )
        )

        with mock.patch(
            "providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "No secrets found in ECS task definition", result[0].status_extended
            )
            assert result[0].resource_id == task_name
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:1"
            )

    def test_container_env_var_with_secrets(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []
        ecs_client.task_definitions.append(
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:1",
                region=AWS_REGION,
                environment_variables=[
                    ContainerEnvVariable(
                        name=env_var_name_with_secrets, value=env_var_value_with_secrets
                    )
                ],
            )
        )

        with mock.patch(
            "providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "Potential secret found in ECS in ECS task definition",
                result[0].status_extended,
            )
            assert result[0].resource_id == task_name
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:1"
            )
