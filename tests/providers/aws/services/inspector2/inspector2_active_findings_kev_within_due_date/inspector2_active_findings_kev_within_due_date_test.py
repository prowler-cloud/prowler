from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import (
    Finding,
    Inspector,
    KnownExploitedVulnerability,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

INSPECTOR_ARN = (
    f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
)
FINDING_ARN = f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:finding/0e436649379db5f327e3cf5bb4421d76"
KEV_ID = "CVE-2024-3400"
CHECK_MODULE = "prowler.providers.aws.services.inspector2.inspector2_active_findings_kev_within_due_date.inspector2_active_findings_kev_within_due_date"


def build_inspector(findings=None, status="ENABLED"):
    return Inspector(
        id="Inspector2",
        arn=INSPECTOR_ARN,
        region=AWS_REGION_EU_WEST_1,
        status=status,
        ec2_status="ENABLED",
        ecr_status="ENABLED",
        lambda_status="ENABLED",
        lambda_code_status="ENABLED",
        findings=findings,
    )


def build_finding(vulnerability_id=KEV_ID):
    return Finding(
        arn=FINDING_ARN,
        type="PACKAGE_VULNERABILITY",
        severity="CRITICAL",
        first_observed_at=datetime.now(timezone.utc),
        vulnerability_id=vulnerability_id,
        resource_ids=["i-0123456789abcdef0"],
    )


def build_kev(date_due):
    return KnownExploitedVulnerability(
        id=KEV_ID,
        date_added=datetime(2024, 4, 12, tzinfo=timezone.utc),
        date_due=date_due,
    )


def execute_check(inspectors, known_exploited=None, lookup_failed=None):
    inspector2_client = mock.MagicMock()
    inspector2_client.inspectors = inspectors
    inspector2_client.known_exploited_vulnerabilities = known_exploited or {}
    inspector2_client.vulnerability_lookup_failed = lookup_failed or set()
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.inspector2_client", new=inspector2_client),
    ):
        from prowler.providers.aws.services.inspector2.inspector2_active_findings_kev_within_due_date.inspector2_active_findings_kev_within_due_date import (
            inspector2_active_findings_kev_within_due_date,
        )

        return inspector2_active_findings_kev_within_due_date().execute()


class Test_inspector2_active_findings_kev_within_due_date:
    def test_no_resources(self):
        assert execute_check([]) == []

    def test_inspector_disabled(self):
        assert execute_check([build_inspector(findings=[], status="DISABLED")]) == []

    def test_kev_past_due_date(self):
        result = execute_check(
            [build_inspector(findings=[build_finding()])],
            known_exploited={
                KEV_ID: build_kev(datetime(2024, 4, 19, tzinfo=timezone.utc))
            },
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Inspector2 has active findings in region {AWS_REGION_EU_WEST_1} for CISA Known Exploited Vulnerabilities past their remediation due date: {KEV_ID} (due 2024-04-19)."
        )
        assert result[0].resource_id == "Inspector2"
        assert result[0].resource_arn == INSPECTOR_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_kev_within_due_date(self):
        result = execute_check(
            [build_inspector(findings=[build_finding()])],
            known_exploited={
                KEV_ID: build_kev(datetime.now(timezone.utc) + timedelta(days=7))
            },
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Inspector2 has no active findings in region {AWS_REGION_EU_WEST_1} for CISA Known Exploited Vulnerabilities past their remediation due date."
        )

    def test_no_kev_findings(self):
        result = execute_check(
            [build_inspector(findings=[build_finding("CVE-2022-40897")])]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_kev_status_not_verified(self):
        result = execute_check(
            [build_inspector(findings=[build_finding()])],
            lookup_failed={KEV_ID},
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    def test_findings_not_retrieved(self):
        result = execute_check([build_inspector(findings=None)])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
