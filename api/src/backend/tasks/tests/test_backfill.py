from uuid import uuid4

import pytest
from tasks.jobs.backfill import (
    backfill_compliance_summaries,
    backfill_resource_scan_summaries,
    backfill_scan_category_summaries,
)

from api.models import (
    ComplianceOverviewSummary,
    Finding,
    ResourceScanSummary,
    Scan,
    ScanCategorySummary,
    StateChoices,
)
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status


@pytest.fixture(scope="function")
def resource_scan_summary_data(scans_fixture):
    scan = scans_fixture[0]
    return ResourceScanSummary.objects.create(
        tenant_id=scan.tenant_id,
        scan_id=scan.id,
        resource_id=str(uuid4()),
        service="aws",
        region="us-east-1",
        resource_type="instance",
    )


@pytest.fixture(scope="function")
def get_not_completed_scans(providers_fixture):
    provider_id = providers_fixture[0].id
    tenant_id = providers_fixture[0].tenant_id
    scan_1 = Scan.objects.create(
        tenant_id=tenant_id,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.EXECUTING,
        provider_id=provider_id,
    )
    scan_2 = Scan.objects.create(
        tenant_id=tenant_id,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        provider_id=provider_id,
    )
    return scan_1, scan_2


@pytest.fixture(scope="function")
def findings_with_categories_fixture(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource = resources_fixture[0]

    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_with_categories",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.critical,
        impact_extended="test impact",
        severity=Severity.critical,
        raw_result={"status": Status.FAIL},
        check_id="test_check",
        check_metadata={"CheckId": "test_check"},
        categories=["gen-ai", "security"],
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])
    return finding


@pytest.fixture(scope="function")
def scan_category_summary_fixture(scans_fixture):
    scan = scans_fixture[0]
    return ScanCategorySummary.objects.create(
        tenant_id=scan.tenant_id,
        scan=scan,
        category="existing-category",
        severity=Severity.critical,
        total_findings=1,
        failed_findings=0,
        new_failed_findings=0,
    )


@pytest.mark.django_db
class TestBackfillResourceScanSummaries:
    def test_already_backfilled(self, resource_scan_summary_data):
        tenant_id = resource_scan_summary_data.tenant_id
        scan_id = resource_scan_summary_data.scan_id

        result = backfill_resource_scan_summaries(tenant_id, scan_id)

        assert result == {"status": "already backfilled"}

    def test_not_completed_scan(self, get_not_completed_scans):
        for scan_instance in get_not_completed_scans:
            tenant_id = scan_instance.tenant_id
            scan_id = scan_instance.id
            result = backfill_resource_scan_summaries(tenant_id, scan_id)

            assert result == {"status": "scan is not completed"}

    def test_successful_backfill_inserts_one_summary(
        self, resources_fixture, findings_fixture
    ):
        tenant_id = findings_fixture[0].tenant_id
        scan_id = findings_fixture[0].scan_id

        # This scan affects the first two resources
        resources = resources_fixture[:2]

        result = backfill_resource_scan_summaries(tenant_id, scan_id)
        assert result == {"status": "backfilled", "inserted": len(resources)}

        # Verify correct values
        summaries = ResourceScanSummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        )
        assert summaries.count() == len(resources)
        for resource in resources:
            summary = summaries.get(resource_id=resource.id)
            assert summary.resource_id == resource.id
            assert summary.service == resource.service
            assert summary.region == resource.region
            assert summary.resource_type == resource.type

    def test_no_resources_to_backfill(self, scans_fixture):
        scan = scans_fixture[1]  # Failed scan with no findings/resources
        tenant_id = str(scan.tenant_id)
        scan_id = str(scan.id)

        result = backfill_resource_scan_summaries(tenant_id, scan_id)

        assert result == {"status": "no resources to backfill"}


@pytest.mark.django_db
class TestBackfillComplianceSummaries:
    def test_already_backfilled(self, scans_fixture):
        scan = scans_fixture[0]
        tenant_id = str(scan.tenant_id)
        ComplianceOverviewSummary.objects.create(
            tenant_id=scan.tenant_id,
            scan=scan,
            compliance_id="aws_account_security_onboarding_aws",
            requirements_passed=1,
            requirements_failed=0,
            requirements_manual=0,
            total_requirements=1,
        )

        result = backfill_compliance_summaries(tenant_id, str(scan.id))

        assert result == {"status": "already backfilled"}

    def test_not_completed_scan(self, get_not_completed_scans):
        for scan in get_not_completed_scans:
            result = backfill_compliance_summaries(str(scan.tenant_id), str(scan.id))
            assert result == {"status": "scan is not completed"}

    def test_no_compliance_data(self, scans_fixture):
        scan = scans_fixture[1]  # Failed scan with no compliance rows

        result = backfill_compliance_summaries(str(scan.tenant_id), str(scan.id))

        assert result == {"status": "no compliance data to backfill"}

    def test_backfill_creates_compliance_summaries(
        self, tenants_fixture, scans_fixture, compliance_requirements_overviews_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        result = backfill_compliance_summaries(str(tenant.id), str(scan.id))

        expected = {
            "aws_account_security_onboarding_aws": {
                "requirements_passed": 1,
                "requirements_failed": 1,
                "requirements_manual": 1,
                "total_requirements": 3,
            },
            "cis_1.4_aws": {
                "requirements_passed": 0,
                "requirements_failed": 1,
                "requirements_manual": 0,
                "total_requirements": 1,
            },
            "mitre_attack_aws": {
                "requirements_passed": 0,
                "requirements_failed": 1,
                "requirements_manual": 0,
                "total_requirements": 1,
            },
        }

        assert result == {"status": "backfilled", "inserted": len(expected)}

        summaries = ComplianceOverviewSummary.objects.filter(
            tenant_id=str(tenant.id), scan_id=str(scan.id)
        )
        assert summaries.count() == len(expected)

        for summary in summaries:
            assert summary.compliance_id in expected
            expected_counts = expected[summary.compliance_id]
            assert summary.requirements_passed == expected_counts["requirements_passed"]
            assert summary.requirements_failed == expected_counts["requirements_failed"]
            assert summary.requirements_manual == expected_counts["requirements_manual"]
            assert summary.total_requirements == expected_counts["total_requirements"]


@pytest.mark.django_db
class TestBackfillScanCategorySummaries:
    def test_already_backfilled(self, scan_category_summary_fixture):
        tenant_id = scan_category_summary_fixture.tenant_id
        scan_id = scan_category_summary_fixture.scan_id

        result = backfill_scan_category_summaries(str(tenant_id), str(scan_id))

        assert result == {"status": "already backfilled"}

    def test_not_completed_scan(self, get_not_completed_scans):
        for scan in get_not_completed_scans:
            result = backfill_scan_category_summaries(str(scan.tenant_id), str(scan.id))
            assert result == {"status": "scan is not completed"}

    def test_no_categories_to_backfill(self, scans_fixture):
        scan = scans_fixture[1]  # Failed scan with no findings
        result = backfill_scan_category_summaries(str(scan.tenant_id), str(scan.id))
        assert result == {"status": "no categories to backfill"}

    def test_successful_backfill(self, findings_with_categories_fixture):
        finding = findings_with_categories_fixture
        tenant_id = str(finding.tenant_id)
        scan_id = str(finding.scan_id)

        result = backfill_scan_category_summaries(tenant_id, scan_id)

        # 2 categories × 1 severity = 2 rows
        assert result == {"status": "backfilled", "categories_count": 2}

        summaries = ScanCategorySummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        )
        assert summaries.count() == 2
        categories = set(summaries.values_list("category", flat=True))
        assert categories == {"gen-ai", "security"}

        for summary in summaries:
            assert summary.severity == Severity.critical
            assert summary.total_findings == 1
            assert summary.failed_findings == 1
            assert summary.new_failed_findings == 1
