from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.backup.backup_service import BackupPlan

AWS_REGION = "eu-west-1"


class Test_backup_plans_exist:
    def test_no_backup_plans(self):
        backup_client = mock.MagicMock
        backup_client.region = AWS_REGION
        backup_client.backup_plans = []
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_plans_exist.backup_plans_exist import (
                backup_plans_exist,
            )

            check = backup_plans_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No Backup Plan Exist"
            assert result[0].resource_id == "Backups"
            assert result[0].resource_arn == ""
            assert result[0].region == AWS_REGION

    def test_one_backup_plan(self):
        backup_client = mock.MagicMock
        backup_client.region = AWS_REGION
        backup_client.backup_plans = [
            BackupPlan(
                arn="ARN",
                id="MyBackupPlan",
                region=AWS_REGION,
                name="MyBackupPlan",
                version_id="version_id",
                last_execution_date=datetime(2015, 1, 1),
                advanced_settings=[],
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_plans_exist.backup_plans_exist import (
                backup_plans_exist,
            )

            check = backup_plans_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "At least one backup plan exists: " + result[0].resource_id
            )
            assert result[0].resource_id == "MyBackupPlan"
            assert result[0].resource_arn == "ARN"
            assert result[0].region == AWS_REGION
