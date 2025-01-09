from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"


class Test_ecs_task_definitions_logging_block_mode:
    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode import (
                ecs_task_definitions_logging_block_mode,
            )

            check = ecs_task_definitions_logging_block_mode()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_task_definition_no_logconfiguration(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode import (
                ecs_task_definitions_logging_block_mode,
            )

            check = ecs_task_definitions_logging_block_mode()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_task_definition_log_configuration_no_mode(self):
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
                    "environment": [],
                    "logConfiguration": {"logDriver": "awslogs"},
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode import (
                ecs_task_definitions_logging_block_mode,
            )

            check = ecs_task_definitions_logging_block_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} running with logging set to blocking mode on containers: {CONTAINER_NAME}"
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_log_configuration_block_mode(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": True,
                    "user": "root",
                    "environment": [],
                    "logConfiguration": {
                        "logDriver": "awslogs",
                        "options": {
                            "mode": "non-blocking",
                            "max-buffer-size": "25m",
                        },
                    },
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_block_mode.ecs_task_definitions_logging_block_mode import (
                ecs_task_definitions_logging_block_mode,
            )

            check = ecs_task_definitions_logging_block_mode()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} containers has logging configured with non blocking mode."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
