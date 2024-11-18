from unittest.mock import MagicMock, patch

import botocore
from botocore.exceptions import ClientError

from prowler.providers.aws.services.datasync.datasync_service import DataSync
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    # Simulate ResourceNotFoundException for specific ARNs
    if operation_name in ["DescribeTask", "ListTagsForResource"]:
        if "not-found" in kwarg.get("TaskArn", "") or "not-found" in kwarg.get(
            "ResourceArn", ""
        ):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Resource not found",
                    }
                },
                operation_name,
            )
        # Simulate other ClientError
        if "client-error" in kwarg.get("TaskArn", "") or "client-error" in kwarg.get(
            "ResourceArn", ""
        ):
            raise ClientError(
                {
                    "Error": {
                        "Code": "InternalServerError",
                        "Message": "Internal server error",
                    }
                },
                operation_name,
            )
        # Simulate generic exception
        if "generic-error" in kwarg.get("TaskArn", "") or "generic-error" in kwarg.get(
            "ResourceArn", ""
        ):
            raise Exception("Generic error")

    if operation_name == "ListTasks":
        if kwarg.get("generic_error", False):
            raise Exception("Generic error in ListTasks")
        return {
            "Tasks": [
                {
                    "TaskArn": "arn:aws:datasync:eu-west-1:123456789012:task/task-12345678901234567",
                    "Name": "test_task",
                },
                {
                    "TaskArn": "arn:aws:datasync:eu-west-1:123456789012:task/not-found",
                    "Name": "not_found_task",
                },
                {
                    "TaskArn": "arn:aws:datasync:eu-west-1:123456789012:task/client-error",
                    "Name": "client_error_task",
                },
                {
                    "TaskArn": "arn:aws:datasync:eu-west-1:123456789012:task/generic-error",
                    "Name": "generic_error_task",
                },
            ]
        }
    if operation_name == "DescribeTask":
        return {
            "TaskArn": kwarg["TaskArn"],
            "Status": "AVAILABLE",
            "Name": "test_task",
            "CurrentTaskExecutionArn": "arn:aws:datasync:eu-west-1:123456789012:task/task-12345678901234567/execution/exec-12345678901234567",
            "Options": {},
            "SourceLocationArn": "arn:aws:datasync:eu-west-1:123456789012:location/loc-12345678901234567",
            "DestinationLocationArn": "arn:aws:datasync:eu-west-1:123456789012:location/loc-76543210987654321",
            "CloudWatchLogGroupArn": "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/datasync/log-group",
            "Tags": [
                {"Key": "Name", "Value": "test_task"},
            ],
        }

    if operation_name == "ListTagsForResource":
        return {
            "Tags": [
                {"Key": "Name", "Value": "test_task"},
            ],
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
class Test_DataSync_Service:
    # Test DataSync Service initialization
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)
        assert datasync.service == "datasync"

    # Test DataSync clients creation
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)
        for reg_client in datasync.regional_clients.values():
            assert reg_client.__class__.__name__ == "DataSync"

    # Test DataSync session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)
        assert datasync.session.__class__.__name__ == "Session"

    # Test listing DataSync tasks
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_tasks(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)

        task_arn = "arn:aws:datasync:eu-west-1:123456789012:task/task-12345678901234567"
        found_task = None
        for task in datasync.tasks.values():
            if task.arn == task_arn:
                found_task = task
                break

        assert found_task
        assert found_task.name == "test_task"
        assert found_task.region == AWS_REGION_EU_WEST_1

    # Test generic exception in list_tasks
    def test_list_tasks_generic_exception(self):
        aws_provider = set_mocked_aws_provider()

        # Mock the regional client's list_tasks method specifically
        mock_client = MagicMock()
        mock_client.region = AWS_REGION_EU_WEST_1
        mock_client.get_paginator.side_effect = Exception("Generic error in ListTasks")

        datasync = DataSync(aws_provider)
        assert len(datasync.tasks.values()) == 0

    # Test describing DataSync tasks with various exceptions
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_describe_tasks_with_exceptions(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)

        # Check all tasks were processed despite exceptions
        assert len(datasync.tasks.values()) == 4

        # Verify each task type
        tasks_by_name = {task.name: task for task in datasync.tasks.values()}

        # Normal task
        assert "test_task" in tasks_by_name
        assert tasks_by_name["test_task"].status == "AVAILABLE"

        # ResourceNotFoundException task
        assert "not_found_task" in tasks_by_name
        assert not tasks_by_name["not_found_task"].status

        # ClientError task
        assert "client_error_task" in tasks_by_name
        assert not tasks_by_name["client_error_task"].status

        # Generic error task
        assert "generic_error_task" in tasks_by_name
        assert not tasks_by_name["generic_error_task"].status

    # Test listing task tags with various exceptions
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_task_tags_with_exceptions(self):
        aws_provider = set_mocked_aws_provider()
        datasync = DataSync(aws_provider)

        tasks_by_name = {task.name: task for task in datasync.tasks.values()}
        assert tasks_by_name["test_task"].tags == [
            {"Key": "Name", "Value": "test_task"}
        ]

        # Tasks with exceptions should have empty tag lists
        assert tasks_by_name["not_found_task"].tags == []
        assert tasks_by_name["client_error_task"].tags == []
        assert tasks_by_name["generic_error_task"].tags == []
