from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeServices":
        if kwarg["services"] == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-linux-service"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-latest-linux-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/test-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-linux-service",
                        "desiredCount": 1,
                        "launchType": "FARGATE",
                        "platformVersion": "1.4.0",
                        "platformFamily": "Linux",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "DISABLED",
                            },
                        },
                        "tags": [],
                    },
                ],
            }
        elif kwarg["services"] == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-windows-service"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-latest-windows-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/test-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-windows-service",
                        "desiredCount": 1,
                        "launchType": "FARGATE",
                        "platformVersion": "1.0.0",
                        "platformFamily": "Windows",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "DISABLED",
                            },
                        },
                        "tags": [],
                    },
                ],
            }
        elif kwarg["services"] == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-linux-service"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-no-latest-linux-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/test-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-linux-service",
                        "desiredCount": 1,
                        "launchType": "FARGATE",
                        "platformVersion": "1.2.0",
                        "platformFamily": "Linux",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "DISABLED",
                            },
                        },
                        "tags": [],
                    },
                ],
            }
        elif kwarg["services"] == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-windows-service"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-no-latest-windows-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/test-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-windows-service",
                        "desiredCount": 1,
                        "launchType": "FARGATE",
                        "platformVersion": "0.9.0",
                        "platformFamily": "Windows",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "DISABLED",
                            },
                        },
                        "tags": [],
                    },
                ],
            }
    return orig(self, operation_name, kwarg)


class Test_ecs_service_fargate_latest_platform_version:
    def test_no_services(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_service_ec2_type(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="test-cluster")

        ecs_client.create_service(
            cluster="test-cluster",
            serviceName="test-service",
            launchType="EC2",
            platformVersion="1.4.0",
            desiredCount=1,
            clientToken="test-token",
        )

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_service_linux_latest_version(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="test-cluster")

        ecs_client.create_service(
            cluster="test-cluster",
            serviceName="test-latest-linux-service",
            launchType="FARGATE",
            platformVersion="1.4.0",
            desiredCount=1,
            clientToken="test-token",
        )

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        mocked_ecs_client = ECS(mocked_aws_provider)

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=mocked_ecs_client,
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "ECS Service test-latest-linux-service is using latest FARGATE Linux version 1.4.0."
            )
            assert result[0].resource_id == "test-latest-linux-service"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-linux-service"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_service_windows_latest_version(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="test-cluster")

        ecs_client.create_service(
            cluster="test-cluster",
            serviceName="test-latest-windows-service",
            launchType="FARGATE",
            platformVersion="1.0.0",
            desiredCount=1,
            clientToken="test-token",
        )

        ecs_client.audit_config = {
            "fargate_windows_latest_version": "1.0.0",
        }

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "ECS Service test-latest-windows-service is using latest FARGATE Windows version 1.0.0."
            )
            assert result[0].resource_id == "test-latest-windows-service"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-latest-windows-service"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_service_linux_no_latest_version(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="test-cluster")

        ecs_client.create_service(
            cluster="test-cluster",
            serviceName="test-no-latest-linux-service",
            launchType="FARGATE",
            platformVersion="1.2.0",
            desiredCount=1,
            clientToken="test-token",
        )

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "ECS Service test-no-latest-linux-service is not using latest FARGATE Linux version 1.4.0, currently using 1.2.0."
            )
            assert result[0].resource_id == "test-no-latest-linux-service"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-linux-service"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_service_windows_no_latest_version(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="test-cluster")

        ecs_client.create_service(
            cluster="test-cluster",
            serviceName="test-no-latest-windows-service",
            launchType="FARGATE",
            platformVersion="0.9.0",
            desiredCount=1,
            clientToken="test-token",
        )

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_service_fargate_latest_platform_version.ecs_service_fargate_latest_platform_version import (
                ecs_service_fargate_latest_platform_version,
            )

            check = ecs_service_fargate_latest_platform_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "ECS Service test-no-latest-windows-service is not using latest FARGATE Windows version 1.0.0, currently using 0.9.0."
            )
            assert result[0].resource_id == "test-no-latest-windows-service"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/test-cluster/test-no-latest-windows-service"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
