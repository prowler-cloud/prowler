from datetime import datetime, timezone
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
CHECK_MODULE = "prowler.providers.aws.services.inspector2.inspector2_coverage_scan_status_active.inspector2_coverage_scan_status_active"


def build_inspector(status="ENABLED", coverage=None):
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


def build_instance(scan_status_code, scan_status_reason):
    return CoveredResource(
        id=INSTANCE_ID,
        arn=INSTANCE_ARN,
        region=AWS_REGION_EU_WEST_1,
        resource_type="AWS_EC2_INSTANCE",
        scan_type="PACKAGE",
        scan_status_code=scan_status_code,
        scan_status_reason=scan_status_reason,
        last_scanned_at=datetime.now(timezone.utc),
    )


def execute_check(inspectors):
    inspector2_client = mock.MagicMock()
    inspector2_client.inspectors = inspectors
    inspector2_client.audit_config = {}
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ),
        mock.patch(f"{CHECK_MODULE}.inspector2_client", new=inspector2_client),
    ):
        from prowler.providers.aws.services.inspector2.inspector2_coverage_scan_status_active.inspector2_coverage_scan_status_active import (
            inspector2_coverage_scan_status_active,
        )

        return inspector2_coverage_scan_status_active().execute()


class Test_inspector2_coverage_scan_status_active:
    def test_inspector_disabled(self):
        assert execute_check([build_inspector(status="DISABLED", coverage=[])]) == []

    def test_no_covered_resources(self):
        assert execute_check([build_inspector(coverage=[])]) == []

    def test_active_resource(self):
        result = execute_check(
            [build_inspector(coverage=[build_instance("ACTIVE", "SUCCESSFUL")])]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Inspector2 is actively scanning AWS_EC2_INSTANCE {INSTANCE_ID}."
        )
        assert result[0].resource_id == INSTANCE_ID
        assert result[0].resource_arn == INSTANCE_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_inactive_resource(self):
        result = execute_check(
            [
                build_inspector(
                    coverage=[build_instance("INACTIVE", "UNMANAGED_EC2_INSTANCE")]
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Inspector2 is not scanning AWS_EC2_INSTANCE {INSTANCE_ID}: UNMANAGED_EC2_INSTANCE."
        )
        assert result[0].resource_id == INSTANCE_ID

    def test_not_applicable_resource_is_skipped(self):
        assert (
            execute_check(
                [
                    build_inspector(
                        coverage=[build_instance("INACTIVE", "EC2_INSTANCE_STOPPED")]
                    )
                ]
            )
            == []
        )

    def test_coverage_not_retrieved(self):
        result = execute_check([build_inspector(coverage=None)])

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Inspector2 coverage could not be retrieved in region {AWS_REGION_EU_WEST_1}; verify the inspector2:ListCoverage permission."
        )
        assert result[0].resource_arn == INSPECTOR_ARN
