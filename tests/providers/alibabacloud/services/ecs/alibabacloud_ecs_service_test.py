from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestECSService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_service.ECS.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import ECS

            ecs_client = ECS(alibabacloud_provider)
            ecs_client.service = "ecs"
            ecs_client.provider = alibabacloud_provider
            ecs_client.regional_clients = {}

            assert ecs_client.service == "ecs"
            assert ecs_client.provider == alibabacloud_provider
