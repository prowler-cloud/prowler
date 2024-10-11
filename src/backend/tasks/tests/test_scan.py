import json
from unittest.mock import patch, MagicMock

import pytest

from api.models import StateChoices, StatusChoices, Severity, Finding, Resource
from tasks.jobs.scan import perform_prowler_scan, _create_finding_delta


@pytest.mark.django_db
class TestPerformScan:
    @patch("tasks.jobs.scan.ProwlerScan")
    @patch("tasks.jobs.scan.initialize_prowler_provider")
    @patch("api.db_utils.tenant_transaction")
    def test_perform_prowler_scan_success(
        self,
        mock_tenant_transaction,
        mock_prowler_provider,
        mock_prowler_scan,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        assert len(Finding.objects.all()) == 0
        assert len(Resource.objects.all()) == 0

        tenant, _ = tenants_fixture
        scan, *_ = scans_fixture
        provider, *_ = providers_fixture

        tenant_id = str(tenant.id)
        scan_id = str(scan.id)
        provider_id = str(provider.id)
        checks_to_execute = ["check1", "check2"]

        finding = MagicMock()
        finding.finding_uid = "this_is_a_test_finding_id"
        finding.status = StatusChoices.PASS
        finding.status_extended = "test status extended"
        finding.severity = Severity.medium
        finding.check_id = "check1"
        finding.json.return_value = '{"key": "value"}'
        finding.resource_uid = "resource_uid"
        finding.region = "region"
        finding.service_name = "service_name"
        finding.resource_type = "resource_type"
        mock_prowler_scan.return_value.scan.return_value = [(100, [finding])]

        perform_prowler_scan(tenant_id, scan_id, provider_id, checks_to_execute)

        scan.refresh_from_db()
        scan_finding = Finding.objects.get(scan=scan)
        scan_resource = Resource.objects.get(provider=provider)

        assert scan.tenant == tenant
        assert scan.provider == provider
        assert scan.state == StateChoices.COMPLETED
        assert scan.completed_at is not None
        assert scan.duration is not None
        assert scan.started_at is not None
        assert scan.unique_resource_count == 1
        assert scan.progress == 100
        assert scan_finding.uid == finding.finding_uid
        assert scan_finding.status == finding.status
        assert scan_finding.status_extended == finding.status_extended
        assert scan_finding.severity == finding.severity
        assert scan_finding.check_id == finding.check_id
        assert scan_finding.raw_result == json.loads(finding.json())

        assert scan_resource.tenant == tenant
        assert scan_resource.uid == finding.resource_uid
        assert scan_resource.region == finding.region
        assert scan_resource.service == finding.service_name
        assert scan_resource.type == finding.resource_type

    @patch("tasks.jobs.scan.ProwlerScan")
    @patch("tasks.jobs.scan.initialize_prowler_provider", side_effect=Exception)
    @patch("api.db_utils.tenant_transaction")
    def test_perform_prowler_scan_no_connection(
        self,
        mock_tenant_transaction,
        mock_prowler_provider,
        mock_prowler_scan,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        tenant, _ = tenants_fixture
        scan, *_ = scans_fixture
        provider, *_ = providers_fixture

        tenant_id = str(tenant.id)
        scan_id = str(scan.id)
        provider_id = str(provider.id)
        checks_to_execute = ["check1", "check2"]

        with pytest.raises(ValueError):
            perform_prowler_scan(tenant_id, scan_id, provider_id, checks_to_execute)

        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED

    @pytest.mark.parametrize(
        "last_status, new_status, expected_delta",
        [
            (None, None, Finding.DeltaChoices.NEW),
            (None, StatusChoices.PASS, Finding.DeltaChoices.NEW),
            (StatusChoices.PASS, StatusChoices.PASS, None),
            (StatusChoices.PASS, StatusChoices.FAIL, Finding.DeltaChoices.CHANGED),
            (StatusChoices.FAIL, StatusChoices.PASS, Finding.DeltaChoices.CHANGED),
        ],
    )
    def test_create_finding_delta(self, last_status, new_status, expected_delta):
        assert _create_finding_delta(last_status, new_status) == expected_delta
