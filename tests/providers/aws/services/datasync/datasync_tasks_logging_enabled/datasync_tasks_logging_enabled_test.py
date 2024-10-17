from unittest import TestCase
from unittest.mock import patch

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_ID = "task-12345"
TASK_ARN = f"arn:aws:datasync:{AWS_REGION_US_EAST_1}:123456789012:task/{TASK_ID}"


class Test_datasync_tasks_logging_enabled(TestCase):
    def test_no_tasks(self):
        from prowler.providers.aws.services.datasync.datasync_service import DataSync

        # Set up a mocked AWS provider
        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        # Create a DataSync client with no tasks
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks = []

        with patch(
            "prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled import (
                datasync_tasks_logging_enabled,
            )

            check = datasync_tasks_logging_enabled()
            result = check.execute()
            self.assertEqual(len(result), 0)

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
            cloud_watch_log_group_arn=None,  # Logging not enabled
            tags=[],
        )

        # Create a DataSync client with the task
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks = [task]

        with patch(
            "prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled import (
                datasync_tasks_logging_enabled,
            )

            check = datasync_tasks_logging_enabled()
            result = check.execute()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "FAIL")
            self.assertEqual(
                result[0].status_extended,
                f"DataSync task {TASK_ID} does not have logging enabled.",
            )
            self.assertEqual(result[0].resource_id, TASK_ID)
            self.assertEqual(result[0].resource_arn, TASK_ARN)
            self.assertEqual(result[0].region, AWS_REGION_US_EAST_1)
            self.assertEqual(result[0].resource_tags, [])

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
            cloud_watch_log_group_arn=f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:datasync-log-group",
            tags=[],
        )

        # Create a DataSync client with the task
        datasync_client = DataSync(mocked_aws_provider)
        datasync_client.tasks = [task]

        with patch(
            "prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled.datasync_client",
            new=datasync_client,
        ), patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mocked_aws_provider,
        ):
            from prowler.providers.aws.services.datasync.datasync_tasks_logging_enabled.datasync_tasks_logging_enabled import (
                datasync_tasks_logging_enabled,
            )

            check = datasync_tasks_logging_enabled()
            result = check.execute()
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].status, "PASS")
            self.assertEqual(
                result[0].status_extended,
                f"DataSync task {TASK_ID} has logging enabled.",
            )
            self.assertEqual(result[0].resource_id, TASK_ID)
            self.assertEqual(result[0].resource_arn, TASK_ARN)
            self.assertEqual(result[0].region, AWS_REGION_US_EAST_1)
            self.assertEqual(result[0].resource_tags, [])
