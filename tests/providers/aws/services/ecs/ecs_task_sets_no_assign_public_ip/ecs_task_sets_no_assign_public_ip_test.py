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
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-task-set-no-public-ip"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-latest-linux-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/sample-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-task-set-no-public-ip",
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
                        "taskSets": [
                            {
                                "id": "ecs-svc/task-set-no-public-ip",
                                "taskSetArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-set/sample-cluster/service-task-set-no-public-ip/ecs-svc/task-set-no-public-ip",
                                "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/sample-cluster",
                                "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-task-set-no-public-ip",
                                "networkConfiguration": {
                                    "awsvpcConfiguration": {
                                        "subnets": ["subnet-12345678"],
                                        "securityGroups": ["sg-12345678"],
                                        "assignPublicIp": "DISABLED",
                                    },
                                },
                                "tags": [],
                            }
                        ],
                        "tags": [],
                    },
                ],
            }
        elif kwarg["services"] == [
            f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-task-set-public-ip"
        ]:
            return {
                "services": [
                    {
                        "serviceName": "test-latest-linux-service",
                        "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/sample-cluster",
                        "taskDefinition": "test-task",
                        "loadBalancers": [],
                        "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-with-public-ip",
                        "desiredCount": 1,
                        "launchType": "FARGATE",
                        "platformVersion": "1.4.0",
                        "platformFamily": "Linux",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "ENABLED",
                            },
                        },
                        "taskSets": [
                            {
                                "id": "ecs-svc/task-set-public-ip",
                                "taskSetArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-set/sample-cluster/service-task-set-public-ip/ecs-svc/task-set-public-ip",
                                "clusterArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster/sample-cluster",
                                "serviceArn": f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:service/sample-cluster/service-task-set-public-ip",
                                "networkConfiguration": {
                                    "awsvpcConfiguration": {
                                        "subnets": ["subnet-12345678"],
                                        "securityGroups": ["sg-12345678"],
                                        "assignPublicIp": "ENABLED",
                                    },
                                },
                                "tags": [],
                            }
                        ],
                        "tags": [],
                    },
                ],
            }
    return orig(self, operation_name, kwarg)


class Test_ecs_task_sets_no_assign_public_ip:
    @mock_aws
    def test_no_services(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip import (
                ecs_task_set_no_assign_public_ip,
            )

            check = ecs_task_set_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_task_set_with_no_public_ip(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="sample-cluster")

        ecs_client.create_service(
            cluster="sample-cluster",
            serviceName="service-task-set-no-public-ip",
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-123456"],
                    "securityGroups": ["sg-123456"],
                    "assignPublicIp": "DISABLED",
                }
            },
        )["service"]["serviceArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip import (
                ecs_task_set_no_assign_public_ip,
            )

            check = ecs_task_set_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ECS Task Set ecs-svc/task-set-no-public-ip does not have automatic public IP assignment."
            )
            assert result[0].resource_id == "ecs-svc/task-set-no-public-ip"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-set/sample-cluster/service-task-set-no-public-ip/ecs-svc/task-set-no-public-ip"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_task_set_public_ip(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        ecs_client.create_cluster(clusterName="sample-cluster")

        ecs_client.create_service(
            cluster="sample-cluster",
            serviceName="service-task-set-public-ip",
            desiredCount=1,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-123456"],
                    "securityGroups": ["sg-123456"],
                    "assignPublicIp": "DISABLED",
                }
            },
        )["service"]["serviceArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ), patch(
            "prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip.ecs_client",
            new=ECS(mocked_aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_set_no_assign_public_ip.ecs_task_set_no_assign_public_ip import (
                ecs_task_set_no_assign_public_ip,
            )

            check = ecs_task_set_no_assign_public_ip()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ECS Task Set ecs-svc/task-set-public-ip has automatic public IP assignment."
            )
            assert result[0].resource_id == "ecs-svc/task-set-public-ip"
            assert (
                result[0].resource_arn
                == f"arn:aws:ecs:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:task-set/sample-cluster/service-task-set-public-ip/ecs-svc/task-set-public-ip"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
