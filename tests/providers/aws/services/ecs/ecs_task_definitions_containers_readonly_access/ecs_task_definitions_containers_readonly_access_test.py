from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

TASK_NAME = "test-task-readonly"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
TASK_ARN = f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-definition/{TASK_NAME}:{TASK_REVISION}"


class Test_ecs_task_definitions_containers_readonly_access:
    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_task_definition_all_containers_readonly(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_definition_arn = ecs_client.register_task_definition(
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
            "prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} does not have containers with write access to the root filesystems."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_definition_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_some_containers_not_readonly(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_definition_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": False,
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
            "prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with write access to the root filesystem: {CONTAINER_NAME}"
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_definition_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_mixed_containers(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_definition_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": False,  # Not readonly
                    "privileged": False,
                    "user": "appuser",
                    "environment": [],
                },
                {
                    "name": "readonly-container",
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,  # Readonly
                    "privileged": False,
                    "user": "appuser",
                    "environment": [],
                },
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_containers_readonly_access.ecs_task_definitions_containers_readonly_access import (
                ecs_task_definitions_containers_readonly_access,
            )

            check = ecs_task_definitions_containers_readonly_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with write access to the root filesystem: {CONTAINER_NAME}"
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_definition_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
