from unittest.mock import patch

import botocore

from prowler.providers.aws.services.ecs.ecs_service import ECS
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListTaskDefinitions":
        return {
            "taskDefinitionArns": [
                "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_ecs_task:1"
            ]
        }
    if operation_name == "DescribeTaskDefinition":
        return {
            "taskDefinition": {
                "containerDefinitions": [
                    {
                        "name": "test-container",
                        "image": "test-image",
                        "environment": [
                            {"name": "DB_PASSWORD", "value": "pass-12343"},
                        ],
                    }
                ],
                "networkMode": "host",
                "tags": [],
            }
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

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_ecs_task:1"

        assert len(ecs.task_definitions) == 1
        assert ecs.task_definitions[task_arn].name == "test_ecs_task"
        assert ecs.task_definitions[task_arn].arn == task_arn
        assert ecs.task_definitions[task_arn].revision == "1"
        assert ecs.task_definitions[task_arn].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test describe ECS task definitions
    def test__describe_task_definitions__(self):
        aws_provider = set_mocked_aws_provider()
        ecs = ECS(aws_provider)

        task_arn = "arn:aws:ecs:eu-west-1:123456789012:task-definition/test_ecs_task:1"

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
