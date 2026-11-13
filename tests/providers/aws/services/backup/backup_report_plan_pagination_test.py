from datetime import datetime, timezone

import pytest
from boto3 import client
from botocore.stub import Stubber
from moto import mock_aws

from prowler.providers.aws.services.backup.backup_service import Backup
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


@pytest.mark.parametrize("filter_second_plan", [False, True])
@mock_aws
def test_backup_report_plans_follow_pagination(filter_second_plan):
    """Collect later report plans even when the first page is filtered out."""
    regional_client = client("backup", region_name=AWS_REGION_EU_WEST_1)
    regional_client.region = AWS_REGION_EU_WEST_1
    plans = [
        {
            "ReportPlanArn": f"arn:aws:backup:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:report-plan:plan_{index}",
            "ReportPlanName": f"plan_{index}",
            "LastAttemptedExecutionTime": datetime(2026, 1, index, tzinfo=timezone.utc),
            "LastSuccessfulExecutionTime": datetime(
                2026, 1, index, tzinfo=timezone.utc
            ),
        }
        for index in (1, 2)
    ]
    backup = Backup.__new__(Backup)
    backup.audit_resources = [plans[1]["ReportPlanArn"]] if filter_second_plan else []
    backup.backup_report_plans = []

    with Stubber(regional_client) as stubber:
        stubber.add_response(
            "list_report_plans",
            {"ReportPlans": [plans[0]], "NextToken": "next-page"},
            {},
        )
        stubber.add_response(
            "list_report_plans", {"ReportPlans": [plans[1]]}, {"NextToken": "next-page"}
        )
        backup._list_backup_report_plans(regional_client)

        expected_plans = plans[1:] if filter_second_plan else plans
        assert [plan.arn for plan in backup.backup_report_plans] == [
            plan["ReportPlanArn"] for plan in expected_plans
        ]
        for actual, expected in zip(backup.backup_report_plans, expected_plans):
            assert actual.name == expected["ReportPlanName"]
            assert actual.region == AWS_REGION_EU_WEST_1
            assert (
                actual.last_attempted_execution_date
                == expected["LastAttemptedExecutionTime"]
            )
            assert (
                actual.last_successful_execution_date
                == expected["LastSuccessfulExecutionTime"]
            )
        stubber.assert_no_pending_responses()


@pytest.mark.parametrize("empty_page_has_token", [False, True])
@mock_aws
def test_backup_report_plans_empty_page(empty_page_has_token):
    """An empty page only ends collection when it has no continuation token."""
    regional_client = client("backup", region_name=AWS_REGION_EU_WEST_1)
    regional_client.region = AWS_REGION_EU_WEST_1
    backup = Backup.__new__(Backup)
    backup.audit_resources = []
    backup.backup_report_plans = []
    first_page = {"ReportPlans": []}
    if empty_page_has_token:
        first_page["NextToken"] = "next-page"

    with Stubber(regional_client) as stubber:
        stubber.add_response("list_report_plans", first_page, {})
        if empty_page_has_token:
            stubber.add_response(
                "list_report_plans",
                {"ReportPlans": [], "NextToken": "last-page"},
                {"NextToken": "next-page"},
            )
            stubber.add_response(
                "list_report_plans", {"ReportPlans": []}, {"NextToken": "last-page"}
            )
        backup._list_backup_report_plans(regional_client)
        assert backup.backup_report_plans == []
        stubber.assert_no_pending_responses()
