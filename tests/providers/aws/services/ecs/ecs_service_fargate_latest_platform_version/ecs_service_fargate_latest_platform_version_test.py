from unittest import mock

from prowler.providers.aws.services.ecs.ecs_service import Service
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

SERVICE_ARN = (
    f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-service"
)
SERVICE_NAME = "sample-service"


class Test_ecs_service_fargate_latest_platform_version:
    def test_no_services(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 0

    def test_service_ec2_type(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            launch_type="EC2",
            assign_public_ip=False,
            tags=[],
        )

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 0

    def test_service_linux_latest_version(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            launch_type="FARGATE",
            platform_family="Linux",
            platform_version="1.4.0",
            assign_public_ip=False,
            tags=[],
        )

        ecs_client.audit_config = {
            "fargate_linux_latest_version": "1.4.0",
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"ECS Service {SERVICE_NAME} is using latest FARGATE Linux version 1.4.0."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN

    def test_service_windows_latest_version(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            launch_type="FARGATE",
            platform_family="Windows",
            platform_version="1.0.0",
            assign_public_ip=False,
            tags=[],
        )

        ecs_client.audit_config = {
            "fargate_windows_latest_version": "1.0.0",
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"ECS Service {SERVICE_NAME} is using latest FARGATE Windows version 1.0.0."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN

    def test_service_linux_no_latest_version(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            launch_type="FARGATE",
            platform_family="Linux",
            platform_version="1.2.0",
            assign_public_ip=False,
            tags=[],
        )

        ecs_client.audit_config = {
            "fargate_linux_latest_version": "1.4.0",
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"ECS Service {SERVICE_NAME} is not using latest FARGATE Linux version 1.4.0, currently using 1.2.0."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN

    def test_service_windows_no_latest_version(self):
        ecs_client = mock.MagicMock
        ecs_client.services = {}
        ecs_client.services[SERVICE_ARN] = Service(
            name=SERVICE_NAME,
            arn=SERVICE_ARN,
            region=AWS_REGION_US_EAST_1,
            launch_type="FARGATE",
            platform_family="Windows",
            platform_version="0.9.0",
            assign_public_ip=False,
            tags=[],
        )

        ecs_client.audit_config = {
            "fargate_windows_latest_version": "1.0.0",
        }

        with mock.patch(
            "prowler.providers.aws.services.ecs.ecs_service.ECS",
            ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"ECS Service {SERVICE_NAME} is not using latest FARGATE Windows version 1.0.0, currently using 0.9.0."
            )
            assert result[0].resource_id == SERVICE_NAME
            assert result[0].resource_arn == SERVICE_ARN
