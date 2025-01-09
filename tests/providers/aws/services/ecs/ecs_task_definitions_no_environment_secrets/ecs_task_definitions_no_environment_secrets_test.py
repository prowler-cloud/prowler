from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
ENV_VAR_NAME_NO_SECRETS = "host"
ENV_VAR_VALUE_NO_SECRETS = "localhost:1234"
ENV_VAR_NAME_WITH_SECRETS = "DB_PASSWORD"
ENV_VAR_VALUE_WITH_SECRETS = "pass-12343"


class Test_ecs_task_definitions_no_environment_secrets:
    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_container_env_var_no_secrets(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_NO_SECRETS,
                            "value": ENV_VAR_VALUE_NO_SECRETS,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
            new=ECS(mocked_aws_provider),
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
                == f"No secrets found in variables of ECS task definition {TASK_NAME} with revision {TASK_REVISION}."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_env_var_with_secrets(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_WITH_SECRETS,
                            "value": ENV_VAR_VALUE_WITH_SECRETS,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
            new=ECS(mocked_aws_provider),
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
                == f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> Secret Keyword on line 2."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
