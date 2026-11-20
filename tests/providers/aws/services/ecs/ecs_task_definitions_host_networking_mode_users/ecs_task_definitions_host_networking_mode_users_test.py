from unittest.mock import patch

from boto3 import client
from moto import mock_aws
from pytest import mark

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"


class Test_ecs_task_definitions_host_networking_mode_users:
    @mark.parametrize(
        "user,network_mode,privileged,expected_status",
        [
            ("", "host", False, "FAIL"),
            ("root", "host", False, "FAIL"),
            ("0", "host", False, "FAIL"),
            ("0:0", "host", False, "FAIL"),
            ("0:1000", "host", False, "FAIL"),
            ("0:app", "host", False, "FAIL"),
            ("root:0", "host", False, "FAIL"),
            ("root:1000", "host", False, "FAIL"),
            ("root:app", "host", False, "FAIL"),
            ("1000", "host", False, "PASS"),
            ("1000:0", "host", False, "PASS"),
            ("1000:root", "host", False, "PASS"),
            ("app", "host", False, "PASS"),
            ("app:0", "host", False, "PASS"),
            ("app:root", "host", False, "PASS"),
            ("rootless", "host", False, "PASS"),
            ("0:0", "host", True, "PASS"),
            ("0:0", "bridge", False, "PASS"),
            ("0:0", "awsvpc", False, "PASS"),
            ("0:0", "none", False, "PASS"),
        ],
    )
    @mock_aws
    def test_user_formats(self, user, network_mode, privileged, expected_status):
        """Inspect the user, not its group, while preserving the existing scope."""
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)
        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            networkMode=network_mode,
            containerDefinitions=[
                {
                    "name": "safe-container",
                    "image": "ubuntu",
                    "memory": 128,
                    "user": "1000:root",
                },
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "privileged": privileged,
                    "user": user,
                },
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            result = ecs_task_definitions_host_networking_mode_users().execute()
            assert len(result) == 1
            assert result[0].status == expected_status
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
            if expected_status == "FAIL":
                assert result[0].status_extended == (
                    f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with host network mode and non-privileged containers running as root or with no user specified: {CONTAINER_NAME}"
                )
            elif network_mode == "host":
                assert result[0].status_extended == (
                    f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has host network mode but no containers running as root or with no user specified."
                )
            else:
                assert result[0].status_extended == (
                    f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} does not have host network mode."
                )

    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users import (
                ecs_task_definitions_host_networking_mode_users,
            )

            check = ecs_task_definitions_host_networking_mode_users()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_task_definition_no_host_network_mode(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            networkMode="bridge",
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

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
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
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} does not have host network mode."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_host_mode_container_root_non_privileged(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            networkMode="host",
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "root",
                    "environment": [],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
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
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has containers with host network mode and non-privileged containers running as root or with no user specified: {CONTAINER_NAME}"
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_host_mode_container_privileged(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            networkMode="host",
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": True,
                    "user": "root",
                    "environment": [],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
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
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has host network mode but no containers running as root or with no user specified."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_task_definition_host_mode_container_not_root(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            networkMode="host",
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

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_host_networking_mode_users.ecs_task_definitions_host_networking_mode_users.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
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
                == f"ECS task definition {TASK_NAME} with revision {TASK_REVISION} has host network mode but no containers running as root or with no user specified."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
