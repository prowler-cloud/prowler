from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import Service
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

SERVICE_ARN = (
    f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-service"
)
SERVICE_NAME = "sample-service"


class Test_ecs_service_no_assign_public_ip:
    def test_no_services(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}

        with mock.patch(
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
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            assign_public_ip=False,
            tags=[],
        )

        with mock.patch(
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
                == f"ECS Service {SERVICE_NAME} does not have automatic public IP assignment."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN

    def test_task_definition_no_host_network_mode(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            assign_public_ip=True,
            tags=[],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_no_assign_public_ip.ecs_service_no_assign_public_ip import (
                ecs_service_no_assign_public_ip,
            )

            check = ecs_service_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS Service {SERVICE_NAME} has automatic public IP assignment."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN
