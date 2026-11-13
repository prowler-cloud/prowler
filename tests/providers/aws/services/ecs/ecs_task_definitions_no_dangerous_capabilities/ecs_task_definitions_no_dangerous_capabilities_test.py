from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ecs_task_definitions_no_dangerous_capabilities:
    @mock_aws
    def test_no_task_definitions(self):
        result = self._run_check()
        assert len(result) == 0

    @mock_aws
    def test_safe_capabilities(self):
        ecs = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs.register_task_definition(
            family="safe-task",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "nginx",
                    "memory": 128,
                    "linuxParameters": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
                }
            ],
        )

        result = self._run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "safe-task:1"

    @mock_aws
    def test_dangerous_capabilities(self):
        ecs = client("ecs", region_name=AWS_REGION_US_EAST_1)

        for family, capability in [
            ("sys-admin-task", "SYS_ADMIN"),
            ("all-capabilities-task", "ALL"),
        ]:
            ecs.register_task_definition(
                family=family,
                containerDefinitions=[
                    {
                        "name": "app",
                        "image": "nginx",
                        "memory": 128,
                        "linuxParameters": {"capabilities": {"add": [capability]}},
                    }
                ],
            )

        result = self._run_check()

        statuses = {finding.resource_id: finding.status for finding in result}

        assert statuses == {
            "sys-admin-task:1": "FAIL",
            "all-capabilities-task:1": "FAIL",
        }

    @mock_aws
    def test_mixed_safe_and_dangerous_containers(self):
        ecs = client("ecs", region_name=AWS_REGION_US_EAST_1)

        for family, capabilities in [
            ("safe-first-task", ["NET_BIND_SERVICE", "SYS_ADMIN"]),
            ("dangerous-first-task", ["SYS_ADMIN", "NET_BIND_SERVICE"]),
        ]:
            ecs.register_task_definition(
                family=family,
                containerDefinitions=[
                    {
                        "name": f"container-{index}",
                        "image": "nginx",
                        "memory": 128,
                        "linuxParameters": {"capabilities": {"add": [capability]}},
                    }
                    for index, capability in enumerate(capabilities)
                ],
            )

        result = self._run_check()

        statuses = {finding.resource_id: finding.status for finding in result}

        assert len(result) == 2
        assert statuses == {
            "safe-first-task:1": "FAIL",
            "dangerous-first-task:1": "FAIL",
        }

    @mock_aws
    def test_unavailable_task_definition(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        ecs = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs.register_task_definition(
            family="unavailable-task",
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "nginx",
                    "memory": 128,
                }
            ],
        )

        def mock_describe_task_definition(self, task_definition):
            return None

        with patch.object(
            ECS,
            "_describe_task_definition",
            new=mock_describe_task_definition,
        ):
            result = self._run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "ecs-task-definitions-unavailable"
        assert "unavailable-task:1" in result[0].status_extended
        assert "ecs:DescribeTaskDefinition" in result[0].status_extended
        assert "arn:aws:ecs:" in result[0].status_extended

    @mock_aws
    def test_list_task_definitions_failure(self):
        from botocore.client import BaseClient
        from botocore.exceptions import ClientError

        original_get_paginator = BaseClient.get_paginator

        def mock_get_paginator(self, operation_name):
            if (
                self.meta.service_model.service_name == "ecs"
                and operation_name == "list_task_definitions"
            ):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "Access denied",
                        }
                    },
                    "ListTaskDefinitions",
                )

            return original_get_paginator(self, operation_name)

        with patch.object(BaseClient, "get_paginator", new=mock_get_paginator):
            result = self._run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "ecs-task-definitions-inventory-unavailable"
        assert AWS_REGION_US_EAST_1 in result[0].status_extended
        assert "ecs:ListTaskDefinitions" in result[0].status_extended

    def _run_check(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_dangerous_capabilities.ecs_task_definitions_no_dangerous_capabilities.ecs_client",
                new=ECS(provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_dangerous_capabilities.ecs_task_definitions_no_dangerous_capabilities import (
                ecs_task_definitions_no_dangerous_capabilities,
            )

            check = ecs_task_definitions_no_dangerous_capabilities()
            return check.execute()
