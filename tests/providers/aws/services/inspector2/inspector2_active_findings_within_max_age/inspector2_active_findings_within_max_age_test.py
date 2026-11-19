from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import (
    Finding,
    Inspector,
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
CHECK_MODULE = "prowler.providers.aws.services.inspector2.inspector2_active_findings_within_max_age.inspector2_active_findings_within_max_age"


def build_inspector(oldest_findings=None, status="ENABLED"):
    return Inspector(
        id="Inspector2",
        arn=INSPECTOR_ARN,
        region=AWS_REGION_EU_WEST_1,
        status=status,
        ec2_status="ENABLED",
        ecr_status="ENABLED",
        lambda_status="ENABLED",
        lambda_code_status="ENABLED",
        oldest_findings=oldest_findings,
    )


def build_finding(age_days):
    return Finding(
        arn=FINDING_ARN,
        type="PACKAGE_VULNERABILITY",
        severity="HIGH",
        first_observed_at=datetime.now(timezone.utc)
        - timedelta(days=age_days, hours=1),
        vulnerability_id="CVE-2022-40897",
        resource_ids=["i-0123456789abcdef0"],
    )


def execute_check(inspectors, audit_config=None):
    inspector2_client = mock.MagicMock()
    inspector2_client.inspectors = inspectors
    inspector2_client.audit_config = audit_config or {}
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.inspector2_client", new=inspector2_client),
    ):
        from prowler.providers.aws.services.inspector2.inspector2_active_findings_within_max_age.inspector2_active_findings_within_max_age import (
            inspector2_active_findings_within_max_age,
        )

        return inspector2_active_findings_within_max_age().execute()


class Test_inspector2_active_findings_within_max_age:
    def test_no_resources(self):
        assert execute_check([]) == []

    def test_inspector_disabled(self):
        assert (
            execute_check([build_inspector(oldest_findings=[], status="DISABLED")])
            == []
        )

    def test_no_active_findings(self):
        result = execute_check([build_inspector(oldest_findings=[])])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Inspector2 has no active findings in region {AWS_REGION_EU_WEST_1} first observed more than 192 days ago."
        )
        assert result[0].resource_id == "Inspector2"
        assert result[0].resource_arn == INSPECTOR_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_oldest_finding_within_max_age(self):
        result = execute_check([build_inspector(oldest_findings=[build_finding(30)])])

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_finding_just_over_max_age(self):
        result = execute_check([build_inspector(oldest_findings=[build_finding(192)])])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_stale_finding(self):
        result = execute_check([build_inspector(oldest_findings=[build_finding(400)])])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Inspector2 has active findings in region {AWS_REGION_EU_WEST_1} first observed more than 192 days ago, the oldest 400 days ago."
        )

    def test_custom_max_age_in_message(self):
        result = execute_check(
            [build_inspector(oldest_findings=[build_finding(30)])],
            audit_config={"inspector2_active_finding_max_age_days": 14},
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "first observed more than 14 days ago, the oldest 30 days ago" in (
            result[0].status_extended
        )

    def test_findings_not_retrieved(self):
        result = execute_check([build_inspector(oldest_findings=None)])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
