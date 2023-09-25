from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerEnvVariable,
    TaskDefinition,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
task_name = "test-task"
task_revision = "1"
env_var_name_no_secrets = "host"
env_var_value_no_secrets = "localhost:1234"
env_var_name_with_secrets = "DB_PASSWORD"
env_var_value_with_secrets = "pass-12343"


class Test_ecs_task_definitions_public_ip:
    def test_no_task_definitions(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_public_ip.ecs_task_definitions_public_ip import (
                ecs_task_definitions_public_ip,
            )

            check = ecs_task_definitions_public_ip()
            result = check.execute()
            assert len(result) == 0

    def test_task_definition_with_public_ip(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []
        ecs_client.task_definitions.append(
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
                revision="1",
                region=AWS_REGION,
                environment_variables=[
                    ContainerEnvVariable(
                        name=env_var_name_no_secrets, value=env_var_value_no_secrets
                    )
                ],
                network_mode="awsvpc",
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_public_ip.ecs_task_definitions_public_ip import (
                ecs_task_definitions_public_ip,
            )

            check = ecs_task_definitions_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f'{task_name} with "awsvpc" network mode in use, that implies a public IP assign to the running task.'
            )
            assert result[0].resource_id == f"{task_name}:1"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"
            )

    def test_task_definition_without_public_ip(self):
        ecs_client = mock.MagicMock
        ecs_client.task_definitions = []
        ecs_client.task_definitions.append(
            TaskDefinition(
                name=task_name,
                arn=f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}",
                revision="1",
                region=AWS_REGION,
                environment_variables=[
                    ContainerEnvVariable(
                        name=env_var_name_with_secrets, value=env_var_value_with_secrets
                    )
                ],
                network_mode="test",
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_public_ip.ecs_task_definitions_public_ip import (
                ecs_task_definitions_public_ip,
            )

            check = ecs_task_definitions_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f'{task_name} with no "awsvpc" network mode in use, that implies a public IP assign to the running task.'
            )
            assert result[0].resource_id == f"{task_name}:1"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:task-definition/{task_name}:{task_revision}"
            )
