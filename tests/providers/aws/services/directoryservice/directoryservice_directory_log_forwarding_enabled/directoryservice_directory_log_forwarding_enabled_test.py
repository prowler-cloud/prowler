from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    Directory,
    DirectoryType,
    LogSubscriptions,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


class Test_directoryservice_directory_log_forwarding_enabled:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_log_forwarding_enabled.directoryservice_directory_log_forwarding_enabled import (
                directoryservice_directory_log_forwarding_enabled,
            )

            check = directoryservice_directory_log_forwarding_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_directory_logging_disabled(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                arn=directory_arn,
                id=directory_id,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                log_subscriptions=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_log_forwarding_enabled.directoryservice_directory_log_forwarding_enabled import (
                directoryservice_directory_log_forwarding_enabled,
            )

            check = directoryservice_directory_log_forwarding_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} have log forwarding to CloudWatch disabled."
            )

    def test_one_directory_logging_enabled(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                arn=directory_arn,
                id=directory_id,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                log_subscriptions=[
                    LogSubscriptions(
                        log_group_name="test-log-group",
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
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_log_forwarding_enabled.directoryservice_directory_log_forwarding_enabled import (
                directoryservice_directory_log_forwarding_enabled,
            )

            check = directoryservice_directory_log_forwarding_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} have log forwarding to CloudWatch enabled."
            )
