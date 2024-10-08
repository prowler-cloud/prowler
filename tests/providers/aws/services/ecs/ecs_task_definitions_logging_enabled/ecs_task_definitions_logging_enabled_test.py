from unittest.mock import patch

<<<<<<< HEAD
import botocore

from prowler.providers.aws.services.ecs.ecs_service import (
    ContainerDefinition,
    TaskDefinition,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)
=======
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider
>>>>>>> b27898de1 (chore(ecs): mock all tests using moto (#5326))

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"


make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListTaskDefinitions":
        return {
            "taskDefinitionArns": [
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/test-task:1"
            ]
        }
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "test-image",
                        "environment": [
                            {"name": "DB_PASSWORD", "value": "pass-12343"},
                        ],
                    }
                ],
                "networkMode": "host",
                "tags": [],
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ecs_task_definitions_logging_enabled:
    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

<<<<<<< HEAD
        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
=======
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled.ecs_client",
            new=ECS(mocked_aws_provider),
>>>>>>> b27898de1 (chore(ecs): mock all tests using moto (#5326))
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 0

<<<<<<< HEAD
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_task_definition_no_logconfiguration(self):

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled.ecs_client",
            new=ECS(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers running with no logging configuration: {CONTAINER_NAME}"
            )

    def test_task_definition_no_logdriver(self):
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
                    privileged=True,
                    user="root",
                    environment=[],
                    log_driver="",
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
=======
    @mock_aws
    def test_task_definition_no_logconfiguration(self):
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
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled.ecs_client",
            new=ECS(mocked_aws_provider),
>>>>>>> b27898de1 (chore(ecs): mock all tests using moto (#5326))
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers running with no logging configuration: {CONTAINER_NAME}"
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_privileged_container(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

<<<<<<< HEAD
        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
=======
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
            "prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled.ecs_client",
            new=ECS(mocked_aws_provider),
>>>>>>> b27898de1 (chore(ecs): mock all tests using moto (#5326))
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_logging_enabled.ecs_task_definitions_logging_enabled import (
                ecs_task_definitions_logging_enabled,
            )

            check = ecs_task_definitions_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} containers have logging configured."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
