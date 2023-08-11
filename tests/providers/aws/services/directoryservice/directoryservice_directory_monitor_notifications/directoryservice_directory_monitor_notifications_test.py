from datetime import datetime
from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    Directory,
    DirectoryType,
    EventTopics,
    EventTopicStatus,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_directoryservice_directory_monitor_notifications:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_monitor_notifications.directoryservice_directory_monitor_notifications import (
                directoryservice_directory_monitor_notifications,
            )

            check = directoryservice_directory_monitor_notifications()
            result = check.execute()

            assert len(result) == 0

    def test_one_directory_logging_disabled(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                name=directory_name,
                region=AWS_REGION,
                event_topics=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_monitor_notifications.directoryservice_directory_monitor_notifications import (
                directoryservice_directory_monitor_notifications,
            )

            check = directoryservice_directory_monitor_notifications()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} have SNS messaging disabled."
            )

    def test_one_directory_logging_enabled(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = (
            f"arn:aws:ds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        )
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION,
                event_topics=[
                    EventTopics(
                        topic_arn=f"arn:aws:sns:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:test-topic",
                        topic_name="test-topic",
                        status=EventTopicStatus.Registered,
                        created_date_time=datetime(2022, 1, 1),
                    )
                ],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_monitor_notifications.directoryservice_directory_monitor_notifications import (
                directoryservice_directory_monitor_notifications,
            )

            check = directoryservice_directory_monitor_notifications()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} have SNS messaging enabled."
            )
