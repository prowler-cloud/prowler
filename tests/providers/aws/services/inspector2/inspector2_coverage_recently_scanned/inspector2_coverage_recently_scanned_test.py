from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import (
    CoveredResource,
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
INSTANCE_ID = "i-0123456789abcdef0"
INSTANCE_ARN = (
    f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/{INSTANCE_ID}"
)
CHECK_MODULE = "prowler.providers.aws.services.inspector2.inspector2_coverage_recently_scanned.inspector2_coverage_recently_scanned"


def build_inspector(coverage=None, status="ENABLED"):
    return Inspector(
        id="Inspector2",
        arn=INSPECTOR_ARN,
        region=AWS_REGION_EU_WEST_1,
        status=status,
        ec2_status="ENABLED",
        ecr_status="ENABLED",
        lambda_status="ENABLED",
        lambda_code_status="ENABLED",
        coverage=coverage,
    )


def build_instance(
    days_since_scan=None, scan_status_code="ACTIVE", scan_status_reason="SUCCESSFUL"
):
    last_scanned_at = (
        datetime.now(timezone.utc) - timedelta(days=days_since_scan, hours=1)
        if days_since_scan is not None
        else None
    )
    return CoveredResource(
        id=INSTANCE_ID,
        arn=INSTANCE_ARN,
        region=AWS_REGION_EU_WEST_1,
        resource_type="AWS_EC2_INSTANCE",
        scan_type="PACKAGE",
        scan_status_code=scan_status_code,
        scan_status_reason=scan_status_reason,
        last_scanned_at=last_scanned_at,
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
        from prowler.providers.aws.services.inspector2.inspector2_coverage_recently_scanned.inspector2_coverage_recently_scanned import (
            inspector2_coverage_recently_scanned,
        )

        return inspector2_coverage_recently_scanned().execute()


class Test_inspector2_coverage_recently_scanned:
    def test_no_resources(self):
        assert execute_check([]) == []

    def test_inspector_disabled(self):
        assert execute_check([build_inspector(status="DISABLED", coverage=[])]) == []

    def test_recently_scanned_resource(self):
        result = execute_check([build_inspector(coverage=[build_instance(1)])])

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AWS_EC2_INSTANCE {INSTANCE_ID} was last scanned by Inspector2 within the last 3 days."
        )
        assert result[0].resource_id == INSTANCE_ID
        assert result[0].resource_arn == INSTANCE_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_stale_resource(self):
        result = execute_check([build_inspector(coverage=[build_instance(10)])])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS_EC2_INSTANCE {INSTANCE_ID} was last scanned by Inspector2 more than 3 days ago."
        )

    def test_resource_scanned_just_over_max_days(self):
        result = execute_check([build_inspector(coverage=[build_instance(3)])])

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_custom_max_days(self):
        result = execute_check(
            [build_inspector(coverage=[build_instance(10)])],
            audit_config={"inspector2_max_days_since_last_scan": 14},
        )

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_resource_without_recorded_scan(self):
        result = execute_check([build_inspector(coverage=[build_instance(None)])])

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS_EC2_INSTANCE {INSTANCE_ID} has no recorded Inspector2 scan."
        )

    def test_pending_initial_scan_is_skipped(self):
        assert (
            execute_check(
                [
                    build_inspector(
                        coverage=[
                            build_instance(
                                None, scan_status_reason="PENDING_INITIAL_SCAN"
                            )
                        ]
                    )
                ]
            )
            == []
        )

    def test_inactive_resource_is_skipped(self):
        assert (
            execute_check(
                [
                    build_inspector(
                        coverage=[
                            build_instance(
                                10,
                                scan_status_code="INACTIVE",
                                scan_status_reason="NO_INVENTORY",
                            )
                        ]
                    )
                ]
            )
            == []
        )

    def test_coverage_not_retrieved(self):
        result = execute_check([build_inspector(coverage=None)])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_arn == INSPECTOR_ARN
