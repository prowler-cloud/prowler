from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    ContainerEnvVariable,
    TaskDefinition,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
task_name = "test-task"
task_revision = "1"
task_arn = f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"
env_var_name_no_secrets = "host"
env_var_value_no_secrets = "localhost:1234"
env_var_name_with_secrets = "DB_PASSWORD"
env_var_value_with_secrets = "pass-12343"


class Test_ecs_task_definitions_no_environment_secrets:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 0

    def test_container_env_var_no_secrets(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
            revision="1",
            region=AWS_REGION,
            container_definitions=[
                ContainerDefinition(
                    name="container1",
                    privileged=False,
                    user="",
                    environment=[
                        ContainerEnvVariable(
                            name=env_var_name_no_secrets, value=env_var_value_no_secrets
                        )
                    ],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in variables of ECS task definition {task_name} with revision {task_revision}."
            )
            assert result[0].resource_id == f"{task_name}:1"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"
            )

    def test_container_env_var_with_secrets(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = {}
        ecs_client.task_definitions[task_arn] = TaskDefinition(
            name=task_name,
            arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
            revision="1",
            region=AWS_REGION,
            container_definitions=[
                ContainerDefinition(
                    name="container1",
                    privileged=False,
                    user="",
                    environment=[
                        ContainerEnvVariable(
                            name=env_var_name_with_secrets,
                            value=env_var_value_with_secrets,
                        )
                    ],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secrets found in ECS task definition {task_name} with revision {task_revision}: Secrets in container container1 -> Secret Keyword on line 2."
            )
            assert result[0].resource_id == f"{task_name}:1"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"
            )
