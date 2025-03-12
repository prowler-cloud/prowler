from unittest.mock import patch

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_ID = "task-12345"
TASK_ARN = f"arn:aws:datasync:{AWS_REGION_US_EAST_1}:123456789012:task/{TASK_ID}"


class Test_datasync_task_logging_enabled:
    def test_no_tasks(self):
        from prowler.providers.aws.services.datasync.datasync_service import DataSync

        # Set up a mocked AWS provider
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Create a DataSync client with no tasks
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks = {}

        with patch(
            "prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled import (
                datasync_task_logging_enabled,
            )

            check = datasync_task_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_task_without_logging(self):
        from prowler.providers.aws.services.datasync.datasync_service import (
            DataSync,
            DataSyncTask,
        )

        # Set up a mocked AWS provider
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Create a DataSync task without logging enabled
        task = DataSyncTask(
            id=TASK_ID,
            arn=TASK_ARN,
            name="TestTask",
            region=AWS_REGION_US_EAST_1,
            cloudwatch_log_group_arn=None,  # Logging not enabled
            tags=[],
        )

        # Create a DataSync client with the task
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks[TASK_ARN] = task

        with patch(
            "prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled import (
                datasync_task_logging_enabled,
            )

            check = datasync_task_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"DataSync task {task.name} does not have logging enabled."
            )
            assert result[0].resource_id == TASK_ID
            assert result[0].resource_arn == TASK_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    def test_task_with_logging(self):
        from prowler.providers.aws.services.datasync.datasync_service import (
            DataSync,
            DataSyncTask,
        )

        # Set up a mocked AWS provider
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Create a DataSync task with logging enabled
        task = DataSyncTask(
            id=TASK_ID,
            arn=TASK_ARN,
            name="TestTask",
            region=AWS_REGION_US_EAST_1,
            cloudwatch_log_group_arn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:datasync-log-group",
            tags=[],
        )

        # Create a DataSync client with the task
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks[TASK_ARN] = task

        with patch(
            "prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_task_logging_enabled.datasync_task_logging_enabled import (
                datasync_task_logging_enabled,
            )

            check = datasync_task_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"DataSync task {task.name} has logging enabled."
            )
            assert result[0].resource_id == TASK_ID
            assert result[0].resource_arn == TASK_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
