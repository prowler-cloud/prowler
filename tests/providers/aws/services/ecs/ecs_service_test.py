from unittest.mock import patch

import botocore

from prowler.providers.aws.services.ecs.ecs_service import ECS
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListTaskDefinitions":
        return {
            "taskDefinitionArns": [
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"
            ]
        }
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "test-image",
                        "logConfiguration": {
                            "logDriver": "awslogs",
                            "options": {
                                "mode": "non-blocking",
                                "max-buffer-size": "25m",
                            },
                        },
                        "environment": [
                            {"name": "DB_PASSWORD", "value": "pass-12343"},
                        ],
                    }
                ],
                "networkMode": "host",
                "pidMode": "host",
                "tags": [],
            }
        }
    if operation_name == "ListServices":
        return {
            "serviceArns": [
                "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service"
            ]
        }
    if operation_name == "DescribeServices":
        return {
            "services": [
                {
                    "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service",
                    "serviceName": "test_ecs_service",
                    "networkConfiguration": {
                        "awsvpcConfiguration": {
                            "subnets": ["subnet-12345678"],
                            "securityGroups": ["sg-12345678"],
                            "assignPublicIp": "ENABLED",
                        }
                    },
                    "launchType": "FARGATE",
                    "platformVersion": "1.4.0",
                    "platformFamily": "Linux",
                    "taskSets": [
                        {
                            "id": "ecs-svc/task-set",
                            "taskSetArn": "arn:aws:ecs:eu-west-1:123456789012:task-set/test_cluster_1/test_ecs_service/ecs-svc/task-set",
                            "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
                            "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service",
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
                }
            ]
        }
    if operation_name == "ListClusters":
        return {
            "clusterArns": [
                "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
            ]
        }
    if operation_name == "DescribeClusters":
        return {
            "clusters": [
                {
                    "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1",
                    "clusterName": "test_cluster_1",
                    "status": "ACTIVE",
                    "tags": [{"key": "Name", "value": "test_cluster_1"}],
                    "settings": [
                        {"name": "containerInsights", "value": "enabled"},
                    ],
                    "registeredContainerInstancesCount": 5,
                    "runningTasksCount": 10,
                    "pendingTasksCount": 1,
                    "activeServicesCount": 2,
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ECS_Service:
    # Test ECS Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)
        assert ecs.service == "ecs"

    # Test ECS client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)
        for reg_client in ecs.regional_clients.values():
            assert reg_client.__class__.__name__ == "ECS"

    # Test ECS session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)
        assert ecs.session.__class__.__name__ == "Session"

    # Test list ECS task definitions
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_task_definitions(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"

        assert len(ecs.task_definitions) == 1
        assert ecs.task_definitions[task_arn].name == "test_ecs_task"
        assert ecs.task_definitions[task_arn].arn == task_arn
        assert ecs.task_definitions[task_arn].revision == "1"
        assert ecs.task_definitions[task_arn].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS task definitions
    def test_describe_task_definitions(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_cluster_1/test_ecs_task:1"

        assert len(ecs.task_definitions) == 1
        assert ecs.task_definitions[task_arn].name == "test_ecs_task"
        assert ecs.task_definitions[task_arn].arn == task_arn
        assert ecs.task_definitions[task_arn].revision == "1"
        assert ecs.task_definitions[task_arn].region == AWS_REGION_EU_WEST_1
        assert len(ecs.task_definitions[task_arn].container_definitions) == 1
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].name
            == "test-container"
        )
        assert (
            len(ecs.task_definitions[task_arn].container_definitions[0].environment)
            == 1
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].environment[0].name
            == "DB_PASSWORD"
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].environment[0].value
            == "pass-12343"
        )
        assert ecs.task_definitions[task_arn].network_mode == "host"
        assert not ecs.task_definitions[task_arn].container_definitions[0].privileged
        assert ecs.task_definitions[task_arn].container_definitions[0].user == ""
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].log_driver
            == "awslogs"
        )
        assert (
            ecs.task_definitions[task_arn].container_definitions[0].log_option
            == "non-blocking"
        )
        assert ecs.task_definitions[task_arn].pid_mode == "host"
        assert (
            not ecs.task_definitions[task_arn]
            .container_definitions[0]
            .readonly_rootfilesystem
        )

    # Test list ECS clusters
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_clusters(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        cluster_arn1 = "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"

        assert len(ecs.clusters) == 1
        assert ecs.clusters[cluster_arn1].name == "test_cluster_1"
        assert ecs.clusters[cluster_arn1].arn == cluster_arn1
        assert ecs.clusters[cluster_arn1].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS clusters
    def test_describe_clusters(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        cluster_arn1 = "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"

        assert len(ecs.clusters) == 1
        assert ecs.clusters[cluster_arn1].name == "test_cluster_1"
        assert ecs.clusters[cluster_arn1].arn == cluster_arn1
        assert ecs.clusters[cluster_arn1].region == AWS_REGION_EU_WEST_1
        assert ecs.clusters[cluster_arn1].services
        assert ecs.clusters[cluster_arn1].tags == [
            {"key": "Name", "value": "test_cluster_1"}
        ]
        assert ecs.clusters[cluster_arn1].settings == [
            {"name": "containerInsights", "value": "enabled"}
        ]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS services
    def test_describe_services(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        service_arn = (
            "arn:aws:ecs:eu-west-1:123456789012:service/test_cluster_1/test_ecs_service"
        )

        task_set_arn = "arn:aws:ecs:eu-west-1:123456789012:task-set/test_cluster_1/test_ecs_service/ecs-svc/task-set"

        assert len(ecs.services) == 1
        assert ecs.services[service_arn].name == "test_ecs_service"
        assert ecs.services[service_arn].arn == service_arn
        assert ecs.services[service_arn].region == AWS_REGION_EU_WEST_1
        assert ecs.services[service_arn].assign_public_ip
        assert ecs.services[service_arn].tags == []
        assert ecs.services[service_arn].launch_type == "FARGATE"
        assert ecs.services[service_arn].platform_version == "1.4.0"
        assert ecs.services[service_arn].platform_family == "Linux"
        assert len(ecs.task_sets) == 1
        assert ecs.task_sets[task_set_arn].id == "ecs-svc/task-set"
        assert ecs.task_sets[task_set_arn].arn == task_set_arn
        assert (
            ecs.task_sets[task_set_arn].cluster_arn
            == "arn:aws:ecs:eu-west-1:123456789012:cluster/test_cluster_1"
        )
        assert ecs.task_sets[task_set_arn].service_arn == service_arn
        assert ecs.task_sets[task_set_arn].assign_public_ip == "DISABLED"
        assert ecs.task_sets[task_set_arn].region == AWS_REGION_EU_WEST_1
        assert ecs.task_sets[task_set_arn].tags == []
