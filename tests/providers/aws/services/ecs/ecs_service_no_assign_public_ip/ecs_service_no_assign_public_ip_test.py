from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import Service
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

service_arn = (
    f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-service"
)
service_name = "sample-service"


class Test_ecs_service_no_assign_public_ip:
    def test_no_services(self):
        ecs_client = mock.MagicMock()
        ecs_client.services = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_no_assign_public_ip.ecs_service_no_assign_public_ip import (
                ecs_service_no_assign_public_ip,
            )

            check = ecs_service_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 0

    def test_service_with_no_public_ip(self):
        ecs_client = mock.MagicMock()
        ecs_client.services = {}
        ecs_client.services[service_arn] = Service(
            name=service_name,
            arn=service_arn,
            region=AWS_REGION_US_EAST_1,
            assign_public_ip=False,
            tags=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_no_assign_public_ip.ecs_service_no_assign_public_ip import (
                ecs_service_no_assign_public_ip,
            )

            check = ecs_service_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECS Service '{service_name}' does not assign public IP address"
            )
            assert result[0].resource_id == service_name
            assert result[0].resource_arn == service_arn

    def test_task_definition_no_host_network_mode(self):
        ecs_client = mock.MagicMock
        ecs_client.task_services = {}
        ecs_client.services[service_arn] = Service(
            name=service_name,
            arn=service_arn,
            region=AWS_REGION_US_EAST_1,
            assign_public_ip=True,
            tags=[],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
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
                == f"ECS Service '{service_name}' assigns public IP address"
            )
            assert result[0].resource_id == service_name
            assert result[0].resource_arn == service_arn
