from unittest import mock

from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    Directory,
    DirectoryType,
    SnapshotLimit,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


class Test_directoryservice_directory_snapshots_limit:
    def test_no_directories(self):
        directoryservice_client = mock.MagicMock
        directoryservice_client.directories = {}
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_snapshots_limit.directoryservice_directory_snapshots_limit import (
                directoryservice_directory_snapshots_limit,
            )

            check = directoryservice_directory_snapshots_limit()
            result = check.execute()

            assert len(result) == 0

    def test_one_directory_snapshots_limit_reached(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        manual_snapshots_current_count = 5
        manual_snapshots_limit = 5
        manual_snapshots_limit_reached = True
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                snapshots_limits=SnapshotLimit(
                    manual_snapshots_current_count=manual_snapshots_current_count,
                    manual_snapshots_limit=manual_snapshots_limit,
                    manual_snapshots_limit_reached=manual_snapshots_limit_reached,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_snapshots_limit.directoryservice_directory_snapshots_limit import (
                directoryservice_directory_snapshots_limit,
            )

            check = directoryservice_directory_snapshots_limit()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} reached {manual_snapshots_limit} Snapshots limit."
            )

    def test_one_directory_snapshots_limit_over_threshold(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        manual_snapshots_current_count = 4
        manual_snapshots_limit = 5
        manual_snapshots_limit_reached = False
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                snapshots_limits=SnapshotLimit(
                    manual_snapshots_current_count=manual_snapshots_current_count,
                    manual_snapshots_limit=manual_snapshots_limit,
                    manual_snapshots_limit_reached=manual_snapshots_limit_reached,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_snapshots_limit.directoryservice_directory_snapshots_limit import (
                directoryservice_directory_snapshots_limit,
            )

            check = directoryservice_directory_snapshots_limit()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} is about to reach {manual_snapshots_limit} Snapshots which is the limit."
            )

    def test_one_directory_snapshots_limit_equal_threshold(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        manual_snapshots_current_count = 3
        manual_snapshots_limit = 5
        manual_snapshots_limit_reached = False
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                snapshots_limits=SnapshotLimit(
                    manual_snapshots_current_count=manual_snapshots_current_count,
                    manual_snapshots_limit=manual_snapshots_limit,
                    manual_snapshots_limit_reached=manual_snapshots_limit_reached,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_snapshots_limit.directoryservice_directory_snapshots_limit import (
                directoryservice_directory_snapshots_limit,
            )

            check = directoryservice_directory_snapshots_limit()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} is about to reach {manual_snapshots_limit} Snapshots which is the limit."
            )

    def test_one_directory_snapshots_limit_more_threshold(self):
        directoryservice_client = mock.MagicMock
        directory_name = "test-directory"
        directory_id = "d-12345a1b2"
        directory_arn = f"arn:aws:ds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:directory/d-12345a1b2"
        manual_snapshots_current_count = 1
        manual_snapshots_limit = 5
        manual_snapshots_limit_reached = False
        directoryservice_client.directories = {
            directory_name: Directory(
                name=directory_name,
                id=directory_id,
                arn=directory_arn,
                type=DirectoryType.MicrosoftAD,
                region=AWS_REGION_EU_WEST_1,
                snapshots_limits=SnapshotLimit(
                    manual_snapshots_current_count=manual_snapshots_current_count,
                    manual_snapshots_limit=manual_snapshots_limit,
                    manual_snapshots_limit_reached=manual_snapshots_limit_reached,
                ),
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directoryservice.directoryservice_service.DirectoryService",
            new=directoryservice_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directoryservice.directoryservice_directory_snapshots_limit.directoryservice_directory_snapshots_limit import (
                directoryservice_directory_snapshots_limit,
            )

            check = directoryservice_directory_snapshots_limit()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == directory_id
            assert result[0].resource_arn == directory_arn
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Directory Service {directory_id} is using {manual_snapshots_current_count} out of {manual_snapshots_limit} from the Snapshots Limit."
            )
