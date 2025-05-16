from uuid import uuid4

import pytest
from tasks.jobs.backfill import backfill_resource_scan_summaries

from api.models import ResourceScanSummary, Scan, StateChoices


@pytest.mark.django_db
class TestBackfillResourceScanSummaries:
    @pytest.fixture(scope="function")
    def resource_scan_summary_data(self, scans_fixture):
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
    def get_not_completed_scans(self, providers_fixture):
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
