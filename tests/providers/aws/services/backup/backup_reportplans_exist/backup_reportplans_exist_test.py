from datetime import datetime
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.backup.backup_service import (
    BackupPlan,
    BackupReportPlan,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_backup_reportplans_exist:
    def test_no_backup_plans(self):
        backup_client = mock.MagicMock
        backup_client.region = AWS_REGION
        backup_client.backup_plans = []
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_reportplans_exist.backup_reportplans_exist import (
                backup_reportplans_exist,
            )

            check = backup_reportplans_exist()
            result = check.execute()

            assert len(result) == 0

    def test_no_backup_report_plans(self):
        backup_client = mock.MagicMock
        backup_client.audited_account = AWS_ACCOUNT_NUMBER
        backup_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        backup_client.region = AWS_REGION
        backup_client.audited_partition = "aws"
        backup_client.report_plan_arn_template = f"arn:{backup_client.audited_partition}:backup:{backup_client.region}:{backup_client.audited_account}:report-plan"
        backup_plan_id = str(uuid4()).upper()
        backup_plan_arn = (
            f"arn:aws:backup:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:plan:{backup_plan_id}"
        )
        backup_client.backup_plans = [
            BackupPlan(
                arn=backup_plan_arn,
                id=backup_plan_arn,
                region=AWS_REGION,
                name="MyBackupPlan",
                version_id="version_id",
                last_execution_date=datetime(2015, 1, 1),
                advanced_settings=[],
            )
        ]
        backup_client.backup_report_plans = []
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_reportplans_exist.backup_reportplans_exist import (
                backup_reportplans_exist,
            )

            check = backup_reportplans_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No Backup Report Plan exist."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:backup:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:report-plan"
            )
            assert result[0].region == AWS_REGION

    def test_one_backup_report_plan(self):
        backup_client = mock.MagicMock
        backup_client.audited_account = AWS_ACCOUNT_NUMBER
        backup_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        backup_client.region = AWS_REGION
        backup_client.audited_partition = "aws"
        backup_client.report_plan_arn_template = f"arn:{backup_client.audited_partition}:backup:{backup_client.region}:{backup_client.audited_account}:report-plan"
        backup_plan_id = str(uuid4()).upper()
        backup_plan_arn = (
            f"arn:aws:backup:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:plan:{backup_plan_id}"
        )
        backup_client.backup_plans = [
            BackupPlan(
                arn=backup_plan_arn,
                id=backup_plan_id,
                region=AWS_REGION,
                name="MyBackupPlan",
                version_id="version_id",
                last_execution_date=datetime(2015, 1, 1),
                advanced_settings=[],
            )
        ]
        backup_report_plan_id = str(uuid4()).upper()
        backup_report_plan_arn = f"arn:aws:backup:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:report-plan:MyBackupReportPlan-{backup_report_plan_id}"
        backup_client.backup_report_plans = [
            BackupReportPlan(
                arn=backup_report_plan_arn,
                region=AWS_REGION,
                name="MyBackupReportPlan",
                last_attempted_execution_date=datetime(2015, 1, 1),
                last_successful_execution_date=datetime(2015, 1, 1),
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_reportplans_exist.backup_reportplans_exist import (
                backup_reportplans_exist,
            )

            check = backup_reportplans_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"At least one backup report plan exists: {result[0].resource_id}."
            )
            assert result[0].resource_id == "MyBackupReportPlan"
            assert result[0].resource_arn == backup_report_plan_arn
            assert result[0].region == AWS_REGION
