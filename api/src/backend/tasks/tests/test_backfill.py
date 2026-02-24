from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from tasks.jobs.backfill import (
    backfill_compliance_summaries,
    backfill_provider_compliance_scores,
    backfill_resource_scan_summaries,
    backfill_scan_category_summaries,
    backfill_scan_resource_group_summaries,
)

from api.models import (
    ComplianceOverviewSummary,
    Finding,
    ProviderComplianceScore,
    ResourceScanSummary,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    StateChoices,
    StatusChoices,
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


@pytest.fixture(scope="function")
def findings_with_group_fixture(scans_fixture, resources_fixture):
    scan = scans_fixture[0]
    resource = resources_fixture[0]

    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid="finding_with_group",
        scan=scan,
        delta="new",
        status=Status.FAIL,
        status_extended="test status",
        impact=Severity.high,
        impact_extended="test impact",
        severity=Severity.high,
        raw_result={"status": Status.FAIL},
        check_id="test_check",
        check_metadata={"CheckId": "test_check"},
        resource_groups="ai_ml",
        first_seen_at="2024-01-02T00:00:00Z",
    )
    finding.add_resources([resource])
    return finding


@pytest.fixture(scope="function")
def scan_resource_group_summary_fixture(scans_fixture):
    scan = scans_fixture[0]
    return ScanGroupSummary.objects.create(
        tenant_id=scan.tenant_id,
        scan=scan,
        resource_group="existing-group",
        severity=Severity.high,
        total_findings=1,
        failed_findings=0,
        new_failed_findings=0,
        resources_count=1,
    )


@pytest.mark.django_db
class TestBackfillScanGroupSummaries:
    def test_already_backfilled(self, scan_resource_group_summary_fixture):
        tenant_id = scan_resource_group_summary_fixture.tenant_id
        scan_id = scan_resource_group_summary_fixture.scan_id

        result = backfill_scan_resource_group_summaries(str(tenant_id), str(scan_id))

        assert result == {"status": "already backfilled"}

    def test_not_completed_scan(self, get_not_completed_scans):
        for scan in get_not_completed_scans:
            result = backfill_scan_resource_group_summaries(
                str(scan.tenant_id), str(scan.id)
            )
            assert result == {"status": "scan is not completed"}

    def test_no_resource_groups_to_backfill(self, scans_fixture):
        scan = scans_fixture[1]  # Failed scan with no findings
        result = backfill_scan_resource_group_summaries(
            str(scan.tenant_id), str(scan.id)
        )
        assert result == {"status": "no resource groups to backfill"}

    def test_successful_backfill(self, findings_with_group_fixture):
        finding = findings_with_group_fixture
        tenant_id = str(finding.tenant_id)
        scan_id = str(finding.scan_id)

        result = backfill_scan_resource_group_summaries(tenant_id, scan_id)

        # 1 resource group × 1 severity = 1 row
        assert result == {"status": "backfilled", "resource_groups_count": 1}

        summaries = ScanGroupSummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        )
        assert summaries.count() == 1

        summary = summaries.first()
        assert summary.resource_group == "ai_ml"
        assert summary.severity == Severity.high
        assert summary.total_findings == 1
        assert summary.failed_findings == 1
        assert summary.new_failed_findings == 1
        assert summary.resources_count == 1


@pytest.mark.django_db
class TestBackfillProviderComplianceScores:
    def test_no_completed_scans(self, tenants_fixture):
        tenant = tenants_fixture[2]
        result = backfill_provider_compliance_scores(str(tenant.id))
        assert result == {"status": "no completed scans"}

    def test_no_scans_to_process(self, tenants_fixture, scans_fixture):
        tenant = tenants_fixture[0]
        scan1, scan2, _ = scans_fixture

        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            scan=scan1,
            provider=scan1.provider,
            compliance_id="aws_cis_1.0",
            requirement_id="1.1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan1.completed_at,
        )
        ProviderComplianceScore.objects.create(
            tenant_id=tenant.id,
            scan=scan2,
            provider=scan2.provider,
            compliance_id="aws_cis_1.0",
            requirement_id="1.1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan2.completed_at,
        )

        result = backfill_provider_compliance_scores(str(tenant.id))
        assert result == {"status": "no scans to process"}

    @patch("tasks.jobs.backfill.psycopg_connection")
    def test_successful_backfill_executes_sql_queries(
        self,
        mock_psycopg_connection,
        tenants_fixture,
        scans_fixture,
        settings,
    ):
        """Test successful backfill executes SQL queries and returns correct stats."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        scan2 = scans_fixture[1]

        # Set completed_at to make the scan eligible for backfill
        scan.completed_at = datetime.now(timezone.utc)
        scan.save()
        scan2.state = StateChoices.AVAILABLE
        scan2.completed_at = None
        scan2.save()

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.autocommit = True

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        cursor.rowcount = 5

        result = backfill_provider_compliance_scores(str(tenant.id))

        assert result["status"] == "backfilled"
        assert result["providers_processed"] == 1
        assert result["providers_skipped"] == 0
        assert result["total_upserted"] == 5
        assert result["tenant_summary_count"] == 5
