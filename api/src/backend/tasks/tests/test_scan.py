import csv
import json
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.scan import (
    _ATTACK_SURFACE_MAPPING_CACHE,
    _aggregate_findings_by_region,
    _copy_compliance_requirement_rows,
    _create_compliance_summaries,
    _create_finding_delta,
    _get_attack_surface_mapping_from_provider,
    _normalized_compliance_key,
    _persist_compliance_requirement_rows,
    _process_finding_micro_batch,
    _store_resources,
    aggregate_attack_surface,
    aggregate_category_counts,
    aggregate_findings,
    create_compliance_requirements,
    perform_prowler_scan,
    update_provider_compliance_scores,
)
from tasks.utils import CustomEncoder

from api.db_router import MainRouter
from api.exceptions import ProviderConnectionError
from api.models import (
    Finding,
    MuteRule,
    Provider,
    Resource,
    Scan,
    StateChoices,
    StatusChoices,
)
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status


@contextmanager
def noop_rls_transaction(*args, **kwargs):
    yield


class FakeFinding:
    def __init__(self, **attrs):
        self.metadata = attrs.pop("metadata", {})
        for key, value in attrs.items():
            setattr(self, key, value)

        self.resource_tags = getattr(self, "resource_tags", {})
        self.resource_metadata = getattr(self, "resource_metadata", {})
        self.resource_details = getattr(self, "resource_details", {})
        self.compliance = getattr(self, "compliance", {})
        self.raw = getattr(self, "raw", {})
        self.partition = getattr(self, "partition", "")
        self.muted = getattr(self, "muted", False)

    def get_metadata(self):
        return self.metadata


@pytest.mark.django_db
class TestPerformScan:
    def test_perform_prowler_scan_success(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ) as mock_prowler_compliance_overview_template,
            patch(
                "api.compliance.PROWLER_CHECKS", new_callable=dict
            ) as mock_prowler_checks,
        ):
            # Set up the mock PROWLER_CHECKS
            mock_prowler_checks["aws"] = {
                "check1": {"compliance1"},
                "check2": {"compliance1", "compliance2"},
            }

            # Set up the mock PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE
            mock_prowler_compliance_overview_template["aws"] = {
                "compliance1": {
                    "framework": "Framework 1",
                    "version": "1.0",
                    "provider": "aws",
                    "description": "Description of compliance1",
                    "requirements": {
                        "requirement1": {
                            "name": "Requirement 1",
                            "description": "Description of requirement 1",
                            "attributes": [],
                            "checks": {"check1": None, "check2": None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "total": 2,
                            },
                            "status": "PASS",
                        }
                    },
                    "requirements_status": {
                        "passed": 1,
                        "failed": 0,
                        "manual": 0,
                    },
                    "total_requirements": 1,
                }
            }

            # Ensure the database is empty
            assert Finding.objects.count() == 0
            assert Resource.objects.count() == 0

            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            # Ensure the provider type is 'aws' to match our mocks
            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)
            checks_to_execute = ["check1", "check2"]

            # Mock the findings returned by the prowler scan
            finding = MagicMock()
            finding.uid = "this_is_a_test_finding_id"
            finding.status = StatusChoices.PASS
            finding.status_extended = "test status extended"
            finding.severity = Severity.medium
            finding.check_id = "check1"
            finding.get_metadata.return_value = {"key": "value"}
            finding.resource_uid = "resource_uid"
            finding.resource_name = "resource_name"
            finding.region = "region"
            finding.service_name = "service_name"
            finding.resource_type = "resource_type"
            finding.resource_tags = {"tag1": "value1", "tag2": "value2"}
            finding.muted = False
            finding.raw = {}
            finding.resource_metadata = {"test": "metadata"}
            finding.resource_details = {"details": "test"}
            finding.partition = "partition"
            finding.muted = True
            finding.compliance = {"compliance1": "PASS"}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider.get_regions()
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["region"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, checks_to_execute)

        # Refresh instances from the database
        scan.refresh_from_db()
        scan_finding = Finding.objects.get(scan=scan)
        scan_resource = Resource.objects.get(provider=provider)

        # Assertions
        assert scan.tenant == tenant
        assert scan.provider == provider
        assert scan.state == StateChoices.COMPLETED
        assert scan.completed_at is not None
        assert scan.duration is not None
        assert scan.started_at is not None
        assert scan.unique_resource_count == 1
        assert scan.progress == 100

        assert scan_finding.uid == finding.uid
        assert scan_finding.status == finding.status
        assert scan_finding.status_extended == finding.status_extended
        assert scan_finding.severity == finding.severity
        assert scan_finding.check_id == finding.check_id
        assert scan_finding.raw_result == finding.raw
        assert scan_finding.muted
        assert scan_finding.compliance == finding.compliance
        assert scan_finding.muted_reason == "Muted by mutelist"

        assert scan_resource.tenant == tenant
        assert scan_resource.uid == finding.resource_uid
        assert scan_resource.region == finding.region
        assert scan_resource.service == finding.service_name
        assert scan_resource.type == finding.resource_type
        assert scan_resource.name == finding.resource_name
        assert scan_resource.metadata == json.dumps(
            finding.resource_metadata, cls=CustomEncoder
        )
        assert scan_resource.details == f"{finding.resource_details}"
        assert scan_resource.partition == finding.partition

        # Assert that the resource tags have been created and associated
        tags = scan_resource.tags.all()
        assert tags.count() == 2
        tag_keys = {tag.key for tag in tags}
        tag_values = {tag.value for tag in tags}
        assert tag_keys == set(finding.resource_tags.keys())
        assert tag_values == set(finding.resource_tags.values())

        # Assert that failed_findings_count is 0 (finding is PASS and muted)
        assert scan_resource.failed_findings_count == 0

    @patch("tasks.jobs.scan.ProwlerScan")
    @patch(
        "tasks.jobs.scan.initialize_prowler_provider",
        side_effect=Exception("Connection error"),
    )
    @patch("api.db_utils.rls_transaction")
    def test_perform_prowler_scan_no_connection(
        self,
        mock_rls_transaction,
        mock_initialize_prowler_provider,
        mock_prowler_scan_class,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        tenant_id = str(tenant.id)
        scan_id = str(scan.id)
        provider_id = str(provider.id)
        checks_to_execute = ["check1", "check2"]

        with pytest.raises(ProviderConnectionError):
            perform_prowler_scan(tenant_id, scan_id, provider_id, checks_to_execute)

        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED

        provider.refresh_from_db()
        assert provider.connected is False
        assert isinstance(provider.connection_last_checked_at, datetime)

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

    @patch("api.models.ResourceTag.objects.get_or_create")
    @patch("api.models.Resource.objects.get_or_create")
    @patch("api.db_utils.rls_transaction")
    def test_store_resources_new_resource(
        self,
        mock_rls_transaction,
        mock_get_or_create_resource,
        mock_get_or_create_tag,
    ):
        tenant_id = uuid.uuid4()
        provider_instance = MagicMock()
        provider_instance.id = "provider123"

        finding = MagicMock()
        finding.resource_uid = "resource_uid_123"
        finding.resource_name = "resource_name"
        finding.region = "us-west-1"
        finding.service_name = "service_name"
        finding.resource_type = "resource_type"
        finding.resource_tags = {"tag1": "value1", "tag2": "value2"}

        resource_instance = MagicMock()
        resource_instance.uid = finding.resource_uid
        resource_instance.region = finding.region

        mock_get_or_create_resource.return_value = (resource_instance, True)

        tag_instance = MagicMock()
        mock_get_or_create_tag.return_value = (tag_instance, True)

        resource, resource_uid_tuple = _store_resources(
            finding, str(tenant_id), provider_instance
        )

        mock_get_or_create_resource.assert_called_once_with(
            tenant_id=str(tenant_id),
            provider=provider_instance,
            uid=finding.resource_uid,
            defaults={
                "region": finding.region,
                "service": finding.service_name,
                "type": finding.resource_type,
            },
        )

        assert resource == resource_instance
        assert resource_uid_tuple == (resource_instance.uid, resource_instance.region)
        resource_instance.upsert_or_delete_tags.assert_called_once()

    @patch("api.models.ResourceTag.objects.get_or_create")
    @patch("api.models.Resource.objects.get_or_create")
    @patch("api.db_utils.rls_transaction")
    def test_store_resources_existing_resource(
        self,
        mock_rls_transaction,
        mock_get_or_create_resource,
        mock_get_or_create_tag,
    ):
        tenant_id = uuid.uuid4()
        provider_instance = MagicMock()
        provider_instance.id = "provider456"

        finding = MagicMock()
        finding.resource_uid = "resource_uid_123"
        finding.resource_name = "resource_name"
        finding.region = "us-west-2"
        finding.service_name = "new_service"
        finding.resource_type = "new_type"
        finding.resource_tags = {"tag1": "value1", "tag2": "value2"}

        resource_instance = MagicMock()
        resource_instance.uid = finding.resource_uid
        resource_instance.region = "us-west-1"
        resource_instance.service = "old_service"
        resource_instance.type = "old_type"

        mock_get_or_create_resource.return_value = (resource_instance, False)

        tag_instance = MagicMock()
        mock_get_or_create_tag.return_value = (tag_instance, True)

        resource, resource_uid_tuple = _store_resources(
            finding, str(tenant_id), provider_instance
        )

        mock_get_or_create_resource.assert_called_once_with(
            tenant_id=str(tenant_id),
            provider=provider_instance,
            uid=finding.resource_uid,
            defaults={
                "region": finding.region,
                "service": finding.service_name,
                "type": finding.resource_type,
            },
        )

        # Check that resource fields were updated
        assert resource_instance.region == finding.region
        assert resource_instance.service == finding.service_name
        assert resource_instance.type == finding.resource_type
        resource_instance.save.assert_called_once()

        assert resource == resource_instance
        assert resource_uid_tuple == (resource_instance.uid, resource_instance.region)
        resource_instance.upsert_or_delete_tags.assert_called_once()

    @patch("api.models.ResourceTag.objects.get_or_create")
    @patch("api.models.Resource.objects.get_or_create")
    @patch("api.db_utils.rls_transaction")
    def test_store_resources_with_tags(
        self,
        mock_rls_transaction,
        mock_get_or_create_resource,
        mock_get_or_create_tag,
    ):
        tenant_id = uuid.uuid4()
        provider_instance = MagicMock()
        provider_instance.id = "provider456"

        finding = MagicMock()
        finding.resource_uid = "resource_uid_123"
        finding.resource_name = "resource_name"
        finding.region = "us-west-1"
        finding.service_name = "service_name"
        finding.resource_type = "resource_type"
        finding.resource_tags = {"tag1": "value1", "tag2": "value2"}

        resource_instance = MagicMock()
        resource_instance.uid = finding.resource_uid
        resource_instance.region = finding.region

        mock_get_or_create_resource.return_value = (resource_instance, True)
        tag_instance_1 = MagicMock()
        tag_instance_2 = MagicMock()
        mock_get_or_create_tag.side_effect = [
            (tag_instance_1, True),
            (tag_instance_2, True),
        ]

        resource, resource_uid_tuple = _store_resources(
            finding, str(tenant_id), provider_instance
        )

        mock_get_or_create_tag.assert_any_call(
            tenant_id=str(tenant_id), key="tag1", value="value1"
        )
        mock_get_or_create_tag.assert_any_call(
            tenant_id=str(tenant_id), key="tag2", value="value2"
        )
        resource_instance.upsert_or_delete_tags.assert_called_once()
        tags_passed = resource_instance.upsert_or_delete_tags.call_args[1]["tags"]
        assert tag_instance_1 in tags_passed
        assert tag_instance_2 in tags_passed

        assert resource == resource_instance
        assert resource_uid_tuple == (resource_instance.uid, resource_instance.region)

    def test_perform_prowler_scan_with_failed_findings(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that failed findings increment the failed_findings_count"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            # Ensure the database is empty
            assert Finding.objects.count() == 0
            assert Resource.objects.count() == 0

            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            # Ensure the provider type is 'aws'
            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Mock a FAIL finding that is not muted
            fail_finding = MagicMock()
            fail_finding.uid = "fail_finding_uid"
            fail_finding.status = StatusChoices.FAIL
            fail_finding.status_extended = "test fail status"
            fail_finding.severity = Severity.high
            fail_finding.check_id = "fail_check"
            fail_finding.get_metadata.return_value = {"key": "value"}
            fail_finding.resource_uid = "resource_uid_fail"
            fail_finding.resource_name = "fail_resource"
            fail_finding.region = "us-east-1"
            fail_finding.service_name = "ec2"
            fail_finding.resource_type = "instance"
            fail_finding.resource_tags = {"env": "test"}
            fail_finding.muted = False
            fail_finding.raw = {}
            fail_finding.resource_metadata = {"test": "metadata"}
            fail_finding.resource_details = {"details": "test"}
            fail_finding.partition = "aws"
            fail_finding.compliance = {"compliance1": "FAIL"}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [fail_finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Refresh instances from the database
        scan.refresh_from_db()
        scan_resource = Resource.objects.get(provider=provider)

        # Assert that failed_findings_count is 1 (one FAIL finding not muted)
        assert scan_resource.failed_findings_count == 1

    def test_perform_prowler_scan_multiple_findings_same_resource(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that multiple FAIL findings on the same resource increment the counter correctly"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create multiple findings for the same resource
            # Two FAIL findings (not muted) and one PASS finding
            resource_uid = "shared_resource_uid"

            fail_finding_1 = MagicMock()
            fail_finding_1.uid = "fail_finding_1"
            fail_finding_1.status = StatusChoices.FAIL
            fail_finding_1.status_extended = "fail 1"
            fail_finding_1.severity = Severity.high
            fail_finding_1.check_id = "fail_check_1"
            fail_finding_1.get_metadata.return_value = {"key": "value1"}
            fail_finding_1.resource_uid = resource_uid
            fail_finding_1.resource_name = "shared_resource"
            fail_finding_1.region = "us-east-1"
            fail_finding_1.service_name = "ec2"
            fail_finding_1.resource_type = "instance"
            fail_finding_1.resource_tags = {}
            fail_finding_1.muted = False
            fail_finding_1.raw = {}
            fail_finding_1.resource_metadata = {}
            fail_finding_1.resource_details = {}
            fail_finding_1.partition = "aws"
            fail_finding_1.compliance = {}

            fail_finding_2 = MagicMock()
            fail_finding_2.uid = "fail_finding_2"
            fail_finding_2.status = StatusChoices.FAIL
            fail_finding_2.status_extended = "fail 2"
            fail_finding_2.severity = Severity.medium
            fail_finding_2.check_id = "fail_check_2"
            fail_finding_2.get_metadata.return_value = {"key": "value2"}
            fail_finding_2.resource_uid = resource_uid
            fail_finding_2.resource_name = "shared_resource"
            fail_finding_2.region = "us-east-1"
            fail_finding_2.service_name = "ec2"
            fail_finding_2.resource_type = "instance"
            fail_finding_2.resource_tags = {}
            fail_finding_2.muted = False
            fail_finding_2.raw = {}
            fail_finding_2.resource_metadata = {}
            fail_finding_2.resource_details = {}
            fail_finding_2.partition = "aws"
            fail_finding_2.compliance = {}

            pass_finding = MagicMock()
            pass_finding.uid = "pass_finding"
            pass_finding.status = StatusChoices.PASS
            pass_finding.status_extended = "pass"
            pass_finding.severity = Severity.low
            pass_finding.check_id = "pass_check"
            pass_finding.get_metadata.return_value = {"key": "value3"}
            pass_finding.resource_uid = resource_uid
            pass_finding.resource_name = "shared_resource"
            pass_finding.region = "us-east-1"
            pass_finding.service_name = "ec2"
            pass_finding.resource_type = "instance"
            pass_finding.resource_tags = {}
            pass_finding.muted = False
            pass_finding.raw = {}
            pass_finding.resource_metadata = {}
            pass_finding.resource_details = {}
            pass_finding.partition = "aws"
            pass_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [
                (100, [fail_finding_1, fail_finding_2, pass_finding])
            ]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Refresh instances from the database
        scan_resource = Resource.objects.get(provider=provider, uid=resource_uid)

        # Assert that failed_findings_count is 2 (two FAIL findings, one PASS)
        assert scan_resource.failed_findings_count == 2

    def test_perform_prowler_scan_with_muted_findings(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that muted FAIL findings do not increment the failed_findings_count"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Mock a FAIL finding that is muted
            muted_fail_finding = MagicMock()
            muted_fail_finding.uid = "muted_fail_finding"
            muted_fail_finding.status = StatusChoices.FAIL
            muted_fail_finding.status_extended = "muted fail"
            muted_fail_finding.severity = Severity.high
            muted_fail_finding.check_id = "muted_fail_check"
            muted_fail_finding.get_metadata.return_value = {"key": "value"}
            muted_fail_finding.resource_uid = "muted_resource_uid"
            muted_fail_finding.resource_name = "muted_resource"
            muted_fail_finding.region = "us-east-1"
            muted_fail_finding.service_name = "ec2"
            muted_fail_finding.resource_type = "instance"
            muted_fail_finding.resource_tags = {}
            muted_fail_finding.muted = True
            muted_fail_finding.raw = {}
            muted_fail_finding.resource_metadata = {}
            muted_fail_finding.resource_details = {}
            muted_fail_finding.partition = "aws"
            muted_fail_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [muted_fail_finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Refresh instances from the database
        scan_resource = Resource.objects.get(provider=provider)

        # Assert that failed_findings_count is 0 (FAIL finding is muted)
        assert scan_resource.failed_findings_count == 0

    def test_perform_prowler_scan_reset_failed_findings_count(
        self,
        tenants_fixture,
        providers_fixture,
        resources_fixture,
    ):
        """Test that failed_findings_count is reset to 0 at the beginning of each scan"""
        # Use existing resource from fixture and set initial failed_findings_count
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        resource = resources_fixture[0]

        # Set a non-zero failed_findings_count initially
        resource.failed_findings_count = 5
        resource.save()

        # Create a new scan
        scan = Scan.objects.create(
            name="Reset Test Scan",
            provider=provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            tenant_id=tenant.id,
        )

        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Mock a PASS finding for the existing resource
            pass_finding = MagicMock()
            pass_finding.uid = "reset_test_finding"
            pass_finding.status = StatusChoices.PASS
            pass_finding.status_extended = "reset test pass"
            pass_finding.severity = Severity.low
            pass_finding.check_id = "reset_test_check"
            pass_finding.get_metadata.return_value = {"key": "value"}
            pass_finding.resource_uid = resource.uid
            pass_finding.resource_name = resource.name
            pass_finding.region = resource.region
            pass_finding.service_name = resource.service
            pass_finding.resource_type = resource.type
            pass_finding.resource_tags = {}
            pass_finding.muted = False
            pass_finding.raw = {}
            pass_finding.resource_metadata = {}
            pass_finding.resource_details = {}
            pass_finding.partition = "aws"
            pass_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [pass_finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = [resource.region]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Refresh resource from the database
        resource.refresh_from_db()

        # Assert that failed_findings_count was reset to 0 during the scan
        assert resource.failed_findings_count == 0

    def test_perform_prowler_scan_with_active_mute_rules(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test active MuteRule mutes findings with correct reason"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create active MuteRule with specific finding UIDs
            mute_rule_reason = "Accepted risk - production exception"
            finding_uid_1 = "finding_to_mute_1"
            finding_uid_2 = "finding_to_mute_2"

            MuteRule.objects.create(
                tenant_id=tenant_id,
                name="Production Exception Rule",
                reason=mute_rule_reason,
                enabled=True,
                finding_uids=[finding_uid_1, finding_uid_2],
            )

            # Mock findings: one FAIL and one PASS, both should be muted
            muted_fail_finding = MagicMock()
            muted_fail_finding.uid = finding_uid_1
            muted_fail_finding.status = StatusChoices.FAIL
            muted_fail_finding.status_extended = "muted fail"
            muted_fail_finding.severity = Severity.high
            muted_fail_finding.check_id = "muted_fail_check"
            muted_fail_finding.get_metadata.return_value = {"key": "value"}
            muted_fail_finding.resource_uid = "resource_uid_1"
            muted_fail_finding.resource_name = "resource_1"
            muted_fail_finding.region = "us-east-1"
            muted_fail_finding.service_name = "ec2"
            muted_fail_finding.resource_type = "instance"
            muted_fail_finding.resource_tags = {}
            muted_fail_finding.muted = False
            muted_fail_finding.raw = {}
            muted_fail_finding.resource_metadata = {}
            muted_fail_finding.resource_details = {}
            muted_fail_finding.partition = "aws"
            muted_fail_finding.compliance = {}

            muted_pass_finding = MagicMock()
            muted_pass_finding.uid = finding_uid_2
            muted_pass_finding.status = StatusChoices.PASS
            muted_pass_finding.status_extended = "muted pass"
            muted_pass_finding.severity = Severity.medium
            muted_pass_finding.check_id = "muted_pass_check"
            muted_pass_finding.get_metadata.return_value = {"key": "value"}
            muted_pass_finding.resource_uid = "resource_uid_2"
            muted_pass_finding.resource_name = "resource_2"
            muted_pass_finding.region = "us-east-1"
            muted_pass_finding.service_name = "s3"
            muted_pass_finding.resource_type = "bucket"
            muted_pass_finding.resource_tags = {}
            muted_pass_finding.muted = False
            muted_pass_finding.raw = {}
            muted_pass_finding.resource_metadata = {}
            muted_pass_finding.resource_details = {}
            muted_pass_finding.partition = "aws"
            muted_pass_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [
                (100, [muted_fail_finding, muted_pass_finding])
            ]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Verify findings are muted with correct reason
        fail_finding_db = Finding.objects.get(uid=finding_uid_1)
        pass_finding_db = Finding.objects.get(uid=finding_uid_2)

        assert fail_finding_db.muted
        assert fail_finding_db.muted_reason == mute_rule_reason
        assert fail_finding_db.muted_at is not None

        assert pass_finding_db.muted
        assert pass_finding_db.muted_reason == mute_rule_reason
        assert pass_finding_db.muted_at is not None

        # Verify failed_findings_count is 0 for muted FAIL finding
        resource_1 = Resource.objects.get(uid="resource_uid_1")
        assert resource_1.failed_findings_count == 0

    def test_perform_prowler_scan_with_inactive_mute_rules(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test inactive MuteRule does not mute findings"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create inactive MuteRule
            finding_uid = "finding_inactive_rule"
            MuteRule.objects.create(
                tenant_id=tenant_id,
                name="Inactive Rule",
                reason="Should not apply",
                enabled=False,
                finding_uids=[finding_uid],
            )

            # Mock FAIL finding
            fail_finding = MagicMock()
            fail_finding.uid = finding_uid
            fail_finding.status = StatusChoices.FAIL
            fail_finding.status_extended = "test fail"
            fail_finding.severity = Severity.high
            fail_finding.check_id = "fail_check"
            fail_finding.get_metadata.return_value = {"key": "value"}
            fail_finding.resource_uid = "resource_uid_inactive"
            fail_finding.resource_name = "resource_inactive"
            fail_finding.region = "us-east-1"
            fail_finding.service_name = "ec2"
            fail_finding.resource_type = "instance"
            fail_finding.resource_tags = {}
            fail_finding.muted = False
            fail_finding.raw = {}
            fail_finding.resource_metadata = {}
            fail_finding.resource_details = {}
            fail_finding.partition = "aws"
            fail_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [fail_finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Verify finding is NOT muted
        finding_db = Finding.objects.get(uid=finding_uid)
        assert not finding_db.muted
        assert finding_db.muted_reason is None
        assert finding_db.muted_at is None

        # Verify failed_findings_count increments for FAIL finding
        resource = Resource.objects.get(uid="resource_uid_inactive")
        assert resource.failed_findings_count == 1

    def test_perform_prowler_scan_mutelist_overrides_mute_rules(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test mutelist processor takes precedence over MuteRule"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create active MuteRule
            finding_uid = "finding_both_rules"
            MuteRule.objects.create(
                tenant_id=tenant_id,
                name="Manual Mute Rule",
                reason="Muted by manual rule",
                enabled=True,
                finding_uids=[finding_uid],
            )

            # Mock finding with mutelist processor muted=True
            muted_finding = MagicMock()
            muted_finding.uid = finding_uid
            muted_finding.status = StatusChoices.FAIL
            muted_finding.status_extended = "test"
            muted_finding.severity = Severity.high
            muted_finding.check_id = "test_check"
            muted_finding.get_metadata.return_value = {"key": "value"}
            muted_finding.resource_uid = "resource_both"
            muted_finding.resource_name = "resource_both"
            muted_finding.region = "us-east-1"
            muted_finding.service_name = "ec2"
            muted_finding.resource_type = "instance"
            muted_finding.resource_tags = {}
            muted_finding.muted = True
            muted_finding.raw = {}
            muted_finding.resource_metadata = {}
            muted_finding.resource_details = {}
            muted_finding.partition = "aws"
            muted_finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [muted_finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Verify mutelist reason takes precedence
        finding_db = Finding.objects.get(uid=finding_uid)
        assert finding_db.muted
        assert finding_db.muted_reason == "Muted by mutelist"
        assert finding_db.muted_at is not None

        # Verify failed_findings_count is 0
        resource = Resource.objects.get(uid="resource_both")
        assert resource.failed_findings_count == 0

    def test_perform_prowler_scan_mute_rules_multiple_findings(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test MuteRule with multiple finding UIDs mutes all findings"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create MuteRule with multiple finding UIDs
            mute_rule_reason = "Bulk exception for dev environment"
            finding_uids = [
                "bulk_finding_1",
                "bulk_finding_2",
                "bulk_finding_3",
                "bulk_finding_4",
            ]
            MuteRule.objects.create(
                tenant_id=tenant_id,
                name="Bulk Mute Rule",
                reason=mute_rule_reason,
                enabled=True,
                finding_uids=finding_uids,
            )

            # Mock multiple findings with mixed statuses
            findings = []
            for i, uid in enumerate(finding_uids):
                finding = MagicMock()
                finding.uid = uid
                finding.status = (
                    StatusChoices.FAIL if i % 2 == 0 else StatusChoices.PASS
                )
                finding.status_extended = f"test {i}"
                finding.severity = Severity.medium
                finding.check_id = f"check_{i}"
                finding.get_metadata.return_value = {"key": f"value_{i}"}
                finding.resource_uid = f"resource_bulk_{i}"
                finding.resource_name = f"resource_{i}"
                finding.region = "us-west-2"
                finding.service_name = "lambda"
                finding.resource_type = "function"
                finding.resource_tags = {}
                finding.muted = False
                finding.raw = {}
                finding.resource_metadata = {}
                finding.resource_details = {}
                finding.partition = "aws"
                finding.compliance = {}
                findings.append(finding)

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, findings)]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-west-2"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Verify all findings are muted with same reason
        for uid in finding_uids:
            finding_db = Finding.objects.get(uid=uid)
            assert finding_db.muted
            assert finding_db.muted_reason == mute_rule_reason
            assert finding_db.muted_at is not None

        # Verify all resources have failed_findings_count = 0
        for i in range(len(finding_uids)):
            resource = Resource.objects.get(uid=f"resource_bulk_{i}")
            assert resource.failed_findings_count == 0

    def test_perform_prowler_scan_mute_rules_error_handling(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test scan continues when MuteRule loading fails"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
            patch("api.models.MuteRule.objects.filter") as mock_mute_rule_filter,
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Mock MuteRule.objects.filter to raise exception
            mock_mute_rule_filter.side_effect = Exception("Database error")

            # Mock finding
            finding = MagicMock()
            finding.uid = "finding_error_handling"
            finding.status = StatusChoices.FAIL
            finding.status_extended = "test"
            finding.severity = Severity.high
            finding.check_id = "test_check"
            finding.get_metadata.return_value = {"key": "value"}
            finding.resource_uid = "resource_error"
            finding.resource_name = "resource_error"
            finding.region = "us-east-1"
            finding.service_name = "ec2"
            finding.resource_type = "instance"
            finding.resource_tags = {}
            finding.muted = False
            finding.raw = {}
            finding.resource_metadata = {}
            finding.resource_details = {}
            finding.partition = "aws"
            finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Call the function under test - should not raise
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])

        # Verify scan completed successfully
        scan.refresh_from_db()
        assert scan.state == StateChoices.COMPLETED

        # Verify finding is not muted (mute_rules_cache was empty dict)
        finding_db = Finding.objects.get(uid="finding_error_handling")
        assert not finding_db.muted
        assert finding_db.muted_reason is None

        # Verify failed_findings_count increments
        resource = Resource.objects.get(uid="resource_error")
        assert resource.failed_findings_count == 1

    def test_perform_prowler_scan_muted_at_timestamp(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test muted_at timestamp is set correctly for muted findings"""
        with (
            patch("api.db_utils.rls_transaction"),
            patch(
                "tasks.jobs.scan.initialize_prowler_provider"
            ) as mock_initialize_prowler_provider,
            patch("tasks.jobs.scan.ProwlerScan") as mock_prowler_scan_class,
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE",
                new_callable=dict,
            ),
            patch("api.compliance.PROWLER_CHECKS", new_callable=dict),
        ):
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.AWS
            provider.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)
            provider_id = str(provider.id)

            # Create active MuteRule
            finding_uid = "finding_timestamp_test"
            MuteRule.objects.create(
                tenant_id=tenant_id,
                name="Timestamp Test Rule",
                reason="Testing timestamp",
                enabled=True,
                finding_uids=[finding_uid],
            )

            # Mock finding
            finding = MagicMock()
            finding.uid = finding_uid
            finding.status = StatusChoices.FAIL
            finding.status_extended = "test"
            finding.severity = Severity.high
            finding.check_id = "test_check"
            finding.get_metadata.return_value = {"key": "value"}
            finding.resource_uid = "resource_timestamp"
            finding.resource_name = "resource_timestamp"
            finding.region = "us-east-1"
            finding.service_name = "ec2"
            finding.resource_type = "instance"
            finding.resource_tags = {}
            finding.muted = False
            finding.raw = {}
            finding.resource_metadata = {}
            finding.resource_details = {}
            finding.partition = "aws"
            finding.compliance = {}

            # Mock the ProwlerScan instance
            mock_prowler_scan_instance = MagicMock()
            mock_prowler_scan_instance.scan.return_value = [(100, [finding])]
            mock_prowler_scan_class.return_value = mock_prowler_scan_instance

            # Mock prowler_provider
            mock_prowler_provider_instance = MagicMock()
            mock_prowler_provider_instance.get_regions.return_value = ["us-east-1"]
            mock_initialize_prowler_provider.return_value = (
                mock_prowler_provider_instance
            )

            # Capture time before and after scan
            before_scan = datetime.now(timezone.utc)
            perform_prowler_scan(tenant_id, scan_id, provider_id, [])
            after_scan = datetime.now(timezone.utc)

        # Verify muted_at is within the scan time window
        finding_db = Finding.objects.get(uid=finding_uid)
        assert finding_db.muted
        assert finding_db.muted_at is not None
        assert before_scan <= finding_db.muted_at <= after_scan


# TODO Add tests for aggregations


@pytest.mark.django_db
class TestProcessFindingMicroBatch:
    def test_process_finding_micro_batch_creates_records_and_updates_caches(
        self, tenants_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = scan.provider

        finding = FakeFinding(
            uid="finding-new",
            status=StatusChoices.PASS,
            status_extended="all good",
            severity=Severity.low,
            check_id="s3_public_buckets",
            resource_uid="arn:aws:s3:::bucket-1",
            resource_name="bucket-1",
            region="us-east-1",
            service_name="s3",
            resource_type="bucket",
            resource_tags={"env": "dev", "team": "security"},
            resource_metadata={"owner": "secops"},
            resource_details={"arn": "arn:aws:s3:::bucket-1"},
            partition="aws",
            raw={"status": "PASS"},
            compliance={"cis": {"1.1": "PASS"}},
            metadata={"source": "prowler"},
            muted=False,
        )

        resource_cache = {}
        tag_cache = {}
        last_status_cache = {}
        resource_failed_findings_cache = {}
        unique_resources: set[tuple[str, str]] = set()
        scan_resource_cache: set[tuple[str, str, str, str]] = set()
        mute_rules_cache = {}
        scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
        scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}

        with (
            patch("tasks.jobs.scan.rls_transaction", new=noop_rls_transaction),
            patch("api.db_utils.rls_transaction", new=noop_rls_transaction),
        ):
            _process_finding_micro_batch(
                str(tenant.id),
                [finding],
                scan,
                provider,
                resource_cache,
                tag_cache,
                last_status_cache,
                resource_failed_findings_cache,
                unique_resources,
                scan_resource_cache,
                mute_rules_cache,
                scan_categories_cache,
                scan_resource_groups_cache,
                group_resources_cache,
            )

        created_finding = Finding.objects.get(uid=finding.uid)
        resource = Resource.objects.get(uid=finding.resource_uid)

        assert created_finding.scan_id == scan.id
        assert created_finding.status == StatusChoices.PASS
        assert created_finding.delta == Finding.DeltaChoices.NEW
        assert created_finding.muted is False
        assert created_finding.check_metadata == finding.metadata
        assert created_finding.resource_regions == [finding.region]
        assert created_finding.resource_services == [finding.service_name]
        assert created_finding.resource_types == [finding.resource_type]
        assert created_finding.first_seen_at is not None
        assert created_finding.compliance == finding.compliance

        assert resource.provider_id == provider.id
        assert resource.region == finding.region
        assert resource.service == finding.service_name
        assert resource.type == finding.resource_type
        assert resource.name == finding.resource_name
        assert resource.metadata == json.dumps(
            finding.resource_metadata, cls=CustomEncoder
        )
        assert resource.details == f"{finding.resource_details}"
        assert resource.partition == finding.partition
        assert set(resource.tags.values_list("key", "value")) == set(
            finding.resource_tags.items()
        )
        assert resource.findings.filter(uid=finding.uid).exists()

        assert resource_cache[finding.resource_uid].id == resource.id
        assert resource_failed_findings_cache[finding.resource_uid] == 0
        assert (resource.uid, resource.region) in unique_resources
        assert (
            str(resource.id),
            resource.service,
            resource.region,
            resource.type,
        ) in scan_resource_cache
        assert set(tag_cache.keys()) == set(finding.resource_tags.items())

    def test_process_finding_micro_batch_manual_mute_and_dirty_resources(
        self, tenants_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = scan.provider

        existing_resource = Resource.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-001",
            name="i-001",
            region="us-east-1",
            service="ec2",
            type="instance",
            metadata=json.dumps({"old": "meta"}),
            details="old-details",
            partition="aws-old",
        )

        previous_first_seen = datetime(2024, 1, 1, tzinfo=timezone.utc)

        finding = FakeFinding(
            uid="finding-muted",
            status=StatusChoices.FAIL,
            status_extended="failing",
            severity=Severity.high,
            check_id="ec2_public_instance",
            resource_uid=existing_resource.uid,
            resource_name=existing_resource.name,
            region="eu-west-1",
            service_name="eks",
            resource_type="cluster",
            resource_tags={"team": "devsec"},
            resource_metadata={"owner": "platform"},
            resource_details={"id": existing_resource.name},
            partition="aws",
            raw={"status": "FAIL"},
            compliance={"cis": {"1.2": "FAIL"}},
            metadata={"source": "prowler"},
            muted=False,
        )

        resource_cache = {existing_resource.uid: existing_resource}
        tag_cache = {}
        last_status_cache = {finding.uid: (StatusChoices.PASS, previous_first_seen)}
        resource_failed_findings_cache = {existing_resource.uid: 2}
        unique_resources: set[tuple[str, str]] = set()
        scan_resource_cache: set[tuple[str, str, str, str]] = set()
        mute_rules_cache = {finding.uid: "Muted via rule"}
        scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
        scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}

        with (
            patch("tasks.jobs.scan.rls_transaction", new=noop_rls_transaction),
            patch("api.db_utils.rls_transaction", new=noop_rls_transaction),
        ):
            _process_finding_micro_batch(
                str(tenant.id),
                [finding],
                scan,
                provider,
                resource_cache,
                tag_cache,
                last_status_cache,
                resource_failed_findings_cache,
                unique_resources,
                scan_resource_cache,
                mute_rules_cache,
                scan_categories_cache,
                scan_resource_groups_cache,
                group_resources_cache,
            )

        existing_resource.refresh_from_db()
        created_finding = Finding.objects.get(uid=finding.uid)

        assert created_finding.delta == Finding.DeltaChoices.CHANGED
        assert created_finding.status == StatusChoices.FAIL
        assert created_finding.muted is True
        assert created_finding.muted_reason == "Muted via rule"
        assert created_finding.muted_at is not None
        assert created_finding.first_seen_at == previous_first_seen
        assert created_finding.compliance == finding.compliance
        assert created_finding.resource_regions == [finding.region]
        assert created_finding.resource_services == [finding.service_name]
        assert created_finding.resource_types == [finding.resource_type]
        assert created_finding.scan_id == scan.id

        assert resource_failed_findings_cache[finding.resource_uid] == 2
        assert (finding.resource_uid, finding.region) in unique_resources
        assert (
            str(existing_resource.id),
            finding.service_name,
            finding.region,
            finding.resource_type,
        ) in scan_resource_cache

        assert existing_resource.region == finding.region
        assert existing_resource.service == finding.service_name
        assert existing_resource.type == finding.resource_type
        assert existing_resource.metadata == json.dumps(
            finding.resource_metadata, cls=CustomEncoder
        )
        assert existing_resource.details == f"{finding.resource_details}"
        assert existing_resource.partition == finding.partition
        assert set(existing_resource.tags.values_list("key", "value")) == {
            ("team", "devsec")
        }
        assert existing_resource.findings.filter(uid=finding.uid).exists()

        assert resource_cache[finding.resource_uid].region == finding.region
        assert resource_cache[finding.resource_uid].service == finding.service_name
        assert tag_cache.keys() == {("team", "devsec")}

    def test_process_finding_micro_batch_skips_long_uid(
        self, tenants_fixture, scans_fixture
    ):
        """Test that findings with UID > 300 chars are skipped (temporary workaround)."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = scan.provider

        # Create a finding with UID > 300 chars
        long_uid = (
            "prowler-aws-ec2_instance_public_ip-123456789012-us-east-1-" + "x" * 250
        )
        assert len(long_uid) > 300

        finding_with_long_uid = FakeFinding(
            uid=long_uid,
            status=StatusChoices.FAIL,
            status_extended="public instance",
            severity=Severity.high,
            check_id="ec2_instance_public_ip",
            resource_uid="arn:aws:ec2:us-east-1:123456789012:instance/i-long",
            resource_name="i-long-uid-instance",
            region="us-east-1",
            service_name="ec2",
            resource_type="instance",
            resource_tags={},
            resource_metadata={},
            resource_details={},
            partition="aws",
            raw={},
            compliance={},
            metadata={},
            muted=False,
        )

        # Create a normal finding that should be processed
        normal_finding = FakeFinding(
            uid="finding-normal",
            status=StatusChoices.PASS,
            status_extended="all good",
            severity=Severity.low,
            check_id="s3_bucket_encryption",
            resource_uid="arn:aws:s3:::bucket-normal",
            resource_name="bucket-normal",
            region="us-east-1",
            service_name="s3",
            resource_type="bucket",
            resource_tags={},
            resource_metadata={},
            resource_details={},
            partition="aws",
            raw={},
            compliance={},
            metadata={},
            muted=False,
        )

        resource_cache = {}
        tag_cache = {}
        last_status_cache = {}
        resource_failed_findings_cache = {}
        unique_resources: set[tuple[str, str]] = set()
        scan_resource_cache: set[tuple[str, str, str, str]] = set()
        mute_rules_cache = {}
        scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
        scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}

        with (
            patch("tasks.jobs.scan.rls_transaction", new=noop_rls_transaction),
            patch("api.db_utils.rls_transaction", new=noop_rls_transaction),
            patch("tasks.jobs.scan.logger") as mock_logger,
        ):
            _process_finding_micro_batch(
                str(tenant.id),
                [finding_with_long_uid, normal_finding],
                scan,
                provider,
                resource_cache,
                tag_cache,
                last_status_cache,
                resource_failed_findings_cache,
                unique_resources,
                scan_resource_cache,
                mute_rules_cache,
                scan_categories_cache,
                scan_resource_groups_cache,
                group_resources_cache,
            )

        # Verify the long UID finding was NOT created
        assert not Finding.objects.filter(uid=long_uid).exists()

        # Verify the normal finding WAS created
        assert Finding.objects.filter(uid=normal_finding.uid).exists()

        # Verify logging was called for skipped finding
        assert mock_logger.warning.called
        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
        assert any(
            "Skipping finding with UID exceeding 300 characters" in str(call)
            for call in warning_calls
        )
        assert any(
            f"Scan {scan.id}: Skipped 1 finding(s)" in str(call)
            for call in warning_calls
        )

    def test_process_finding_micro_batch_tracks_categories(
        self, tenants_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = scan.provider

        finding1 = FakeFinding(
            uid="finding-cat-1",
            status=StatusChoices.PASS,
            status_extended="all good",
            severity=Severity.low,
            check_id="genai_check",
            resource_uid="arn:aws:bedrock:::model/test",
            resource_name="test-model",
            region="us-east-1",
            service_name="bedrock",
            resource_type="model",
            resource_tags={},
            resource_metadata={},
            resource_details={},
            partition="aws",
            raw={},
            compliance={},
            metadata={"categories": ["gen-ai", "security"]},
            muted=False,
        )

        finding2 = FakeFinding(
            uid="finding-cat-2",
            status=StatusChoices.FAIL,
            status_extended="bad",
            severity=Severity.high,
            check_id="iam_check",
            resource_uid="arn:aws:iam:::user/test",
            resource_name="test-user",
            region="us-east-1",
            service_name="iam",
            resource_type="user",
            resource_tags={},
            resource_metadata={},
            resource_details={},
            partition="aws",
            raw={},
            compliance={},
            metadata={"categories": ["security", "iam"]},
            muted=False,
        )

        resource_cache = {}
        tag_cache = {}
        last_status_cache = {}
        resource_failed_findings_cache = {}
        unique_resources: set[tuple[str, str]] = set()
        scan_resource_cache: set[tuple[str, str, str, str]] = set()
        mute_rules_cache = {}
        scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
        scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}

        with (
            patch("tasks.jobs.scan.rls_transaction", new=noop_rls_transaction),
            patch("api.db_utils.rls_transaction", new=noop_rls_transaction),
        ):
            _process_finding_micro_batch(
                str(tenant.id),
                [finding1, finding2],
                scan,
                provider,
                resource_cache,
                tag_cache,
                last_status_cache,
                resource_failed_findings_cache,
                unique_resources,
                scan_resource_cache,
                mute_rules_cache,
                scan_categories_cache,
                scan_resource_groups_cache,
                group_resources_cache,
            )

        # finding1: PASS, severity=low, categories=["gen-ai", "security"]
        # finding2: FAIL, severity=high, categories=["security", "iam"]
        # Keys are (category, severity) tuples
        assert set(scan_categories_cache.keys()) == {
            ("gen-ai", "low"),
            ("security", "low"),
            ("security", "high"),
            ("iam", "high"),
        }
        assert scan_categories_cache[("gen-ai", "low")] == {
            "total": 1,
            "failed": 0,
            "new_failed": 0,
        }
        assert scan_categories_cache[("security", "low")] == {
            "total": 1,
            "failed": 0,
            "new_failed": 0,
        }
        assert scan_categories_cache[("security", "high")] == {
            "total": 1,
            "failed": 1,
            "new_failed": 1,
        }
        assert scan_categories_cache[("iam", "high")] == {
            "total": 1,
            "failed": 1,
            "new_failed": 1,
        }

        created_finding1 = Finding.objects.get(uid="finding-cat-1")
        created_finding2 = Finding.objects.get(uid="finding-cat-2")
        assert set(created_finding1.categories) == {"gen-ai", "security"}
        assert set(created_finding2.categories) == {"security", "iam"}


@pytest.mark.django_db
class TestCreateComplianceRequirements:
    def test_create_compliance_requirements_success(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
        resources_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "cis_1.4_aws": {
                    "framework": "CIS AWS Foundations Benchmark",
                    "version": "1.4.0",
                    "requirements": {
                        "1.1": {
                            "description": "Ensure root access key does not exist",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 1,
                            },
                            "status": "PASS",
                        },
                        "1.2": {
                            "description": "Ensure MFA is enabled for root account",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 1,
                                "manual": 0,
                                "total": 1,
                            },
                            "status": "FAIL",
                        },
                    },
                },
            }

            result = create_compliance_requirements(tenant_id, scan_id)

            assert "requirements_created" in result
            assert "regions_processed" in result
            assert "compliance_frameworks" in result

    def test_create_compliance_requirements_with_findings(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 2,
                                "fail": 1,
                                "manual": 0,
                                "total": 3,
                            },
                            "status": "FAIL",
                        },
                    },
                }
            }

            result = create_compliance_requirements(tenant_id, scan_id)

            assert "requirements_created" in result

    def test_create_compliance_requirements_kubernetes_provider(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant = tenants_fixture[0]
            scan = scans_fixture[0]
            provider = providers_fixture[0]

            provider.provider = Provider.ProviderChoices.KUBERNETES
            provider.save()
            scan.provider = provider
            scan.save()

            tenant_id = str(tenant.id)
            scan_id = str(scan.id)

            mock_compliance_template.__getitem__.return_value = {
                "kubernetes_cis": {
                    "framework": "CIS Kubernetes Benchmark",
                    "version": "1.6.0",
                    "requirements": {
                        "1.1": {
                            "description": "Test requirement",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 1,
                            },
                            "status": "PASS",
                        },
                    },
                },
            }

            result = create_compliance_requirements(tenant_id, scan_id)

            assert "regions_processed" in result

    def test_create_compliance_requirements_empty_template(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {}

            result = create_compliance_requirements(tenant_id, scan_id)

            assert result["requirements_created"] == 0

    def test_create_compliance_requirements_error_handling(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch("tasks.jobs.scan.return_prowler_provider") as mock_prowler_provider:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_prowler_provider.side_effect = Exception(
                "Provider initialization failed"
            )

            with pytest.raises(Exception, match="Provider initialization failed"):
                create_compliance_requirements(tenant_id, scan_id)

    def test_create_compliance_requirements_check_status_priority(
        self, tenants_fixture, scans_fixture, findings_fixture
    ):
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch(
                "tasks.jobs.scan._persist_compliance_requirement_rows"
            ) as mock_persist,
            patch("tasks.jobs.scan._create_compliance_summaries"),
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan = scans_fixture[0]
            scan_id = str(scan.id)
            existing_finding = findings_fixture[0]

            pass_finding = Finding.objects.create(
                tenant_id=scan.tenant_id,
                uid="pass-finding",
                scan=scan,
                delta=None,
                status=Status.PASS,
                status_extended="pass status",
                impact=Severity.low,
                impact_extended="",
                severity=Severity.low,
                raw_result={"status": Status.PASS},
                tags={},
                check_id=existing_finding.check_id,
                check_metadata={"CheckId": existing_finding.check_id},
                first_seen_at=datetime.now(timezone.utc),
                muted=False,
            )
            resource = existing_finding.resources.first()
            pass_finding.add_resources([resource])

            mock_compliance_template.__getitem__.return_value = {
                "cis_1.4_aws": {
                    "framework": "CIS AWS Foundations Benchmark",
                    "version": "1.4.0",
                    "requirements": {
                        "1.1": {
                            "description": "Test requirement",
                            "checks": {existing_finding.check_id: None},
                            "checks_status": {
                                "pass": 0,
                                "fail": 0,
                                "manual": 0,
                                "total": 1,
                            },
                            "status": "PASS",
                        },
                    },
                },
            }

            create_compliance_requirements(tenant_id, scan_id)

            mock_persist.assert_called_once()
            persisted_rows = mock_persist.call_args[0][1]
            requirement_row = next(
                row for row in persisted_rows if row["requirement_id"] == "1.1"
            )
            assert requirement_row["requirement_status"] == "FAIL"

    def test_create_compliance_requirements_multiple_regions(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 2,
                                "fail": 0,
                                "manual": 0,
                                "total": 2,
                            },
                            "status": "PASS",
                        }
                    },
                }
            }

            result = create_compliance_requirements(tenant_id, scan_id)

            assert "requirements_created" in result
            assert len(result["regions_processed"]) >= 0

    def test_create_compliance_requirements_mixed_status_requirements(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with patch(
            "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
        ) as mock_compliance_template:
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 2,
                                "fail": 0,
                                "manual": 0,
                                "total": 2,
                            },
                            "status": "PASS",
                        },
                        "req_2": {
                            "description": "Test Requirement 2",
                            "checks": {"test_check_id": None},
                            "checks_status": {
                                "pass": 1,
                                "fail": 1,
                                "manual": 0,
                                "total": 2,
                            },
                            "status": "FAIL",
                        },
                    },
                }
            }

            result = create_compliance_requirements(tenant_id, scan_id)

            assert "requirements_created" in result
            assert result["requirements_created"] >= 0


class TestComplianceRequirementCopy:
    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_streams_csv(
        self, mock_psycopg_connection, settings
    ):
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        captured = {}

        def copy_side_effect(sql, file_obj):
            captured["sql"] = sql
            captured["data"] = file_obj.read()

        cursor.copy_expert.side_effect = copy_side_effect

        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "cisa_aws",
            "framework": "CISA",
            "version": None,
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        mock_psycopg_connection.assert_called_once_with("admin")
        connection.cursor.assert_called_once()
        cursor.execute.assert_called_once()
        cursor.copy_expert.assert_called_once()

        csv_rows = list(csv.reader(StringIO(captured["data"])))
        assert csv_rows[0][0] == str(row["id"])
        assert csv_rows[0][5] == ""
        assert csv_rows[0][-1] == str(row["scan_id"])

    @patch("tasks.jobs.scan.ComplianceRequirementOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    @patch(
        "tasks.jobs.scan._copy_compliance_requirement_rows",
        side_effect=Exception("copy failed"),
    )
    def test_persist_compliance_requirement_rows_fallback(
        self, mock_copy, mock_rls_transaction, mock_bulk_create
    ):
        inserted_at = datetime.now(timezone.utc)
        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "inserted_at": inserted_at,
            "compliance_id": "cisa_aws",
            "framework": "CISA",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        tenant_id = row["tenant_id"]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _persist_compliance_requirement_rows(tenant_id, [row])

        mock_copy.assert_called_once_with(tenant_id, [row])
        mock_rls_transaction.assert_called_once_with(tenant_id)
        mock_bulk_create.assert_called_once()

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 1
        fallback = objects[0]
        assert fallback.version == row["version"]
        assert fallback.compliance_id == row["compliance_id"]

    @patch("tasks.jobs.scan.ComplianceRequirementOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    @patch("tasks.jobs.scan._copy_compliance_requirement_rows")
    def test_persist_compliance_requirement_rows_no_rows(
        self, mock_copy, mock_rls_transaction, mock_bulk_create
    ):
        _persist_compliance_requirement_rows(str(uuid.uuid4()), [])

        mock_copy.assert_not_called()
        mock_rls_transaction.assert_not_called()
        mock_bulk_create.assert_not_called()

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_multiple_rows(
        self, mock_psycopg_connection, settings
    ):
        """Test COPY with multiple rows to ensure batch processing works correctly."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        captured = {}

        def copy_side_effect(sql, file_obj):
            captured["sql"] = sql
            captured["data"] = file_obj.read()

        cursor.copy_expert.side_effect = copy_side_effect

        tenant_id = str(uuid.uuid4())
        scan_id = uuid.uuid4()
        inserted_at = datetime.now(timezone.utc)

        rows = [
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": inserted_at,
                "compliance_id": "cisa_aws",
                "framework": "CISA",
                "version": "1.0",
                "description": "First requirement",
                "region": "us-east-1",
                "requirement_id": "req-1",
                "requirement_status": "PASS",
                "passed_checks": 5,
                "failed_checks": 0,
                "total_checks": 5,
                "scan_id": scan_id,
            },
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": inserted_at,
                "compliance_id": "cisa_aws",
                "framework": "CISA",
                "version": "1.0",
                "description": "Second requirement",
                "region": "us-west-2",
                "requirement_id": "req-2",
                "requirement_status": "FAIL",
                "passed_checks": 3,
                "failed_checks": 2,
                "total_checks": 5,
                "scan_id": scan_id,
            },
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": inserted_at,
                "compliance_id": "aws_foundational_security_aws",
                "framework": "AWS-Foundational-Security-Best-Practices",
                "version": "2.0",
                "description": "Third requirement",
                "region": "eu-west-1",
                "requirement_id": "req-3",
                "requirement_status": "MANUAL",
                "passed_checks": 0,
                "failed_checks": 0,
                "total_checks": 3,
                "scan_id": scan_id,
            },
        ]

        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(tenant_id, rows)

        mock_psycopg_connection.assert_called_once_with("admin")
        connection.cursor.assert_called_once()
        cursor.execute.assert_called_once()
        cursor.copy_expert.assert_called_once()

        csv_rows = list(csv.reader(StringIO(captured["data"])))
        assert len(csv_rows) == 3

        # Validate first row
        assert csv_rows[0][0] == str(rows[0]["id"])
        assert csv_rows[0][1] == tenant_id
        assert csv_rows[0][3] == "cisa_aws"
        assert csv_rows[0][4] == "CISA"
        assert csv_rows[0][6] == "First requirement"
        assert csv_rows[0][7] == "us-east-1"
        assert csv_rows[0][10] == "5"
        assert csv_rows[0][11] == "0"
        assert csv_rows[0][12] == "5"

        # Validate second row
        assert csv_rows[1][0] == str(rows[1]["id"])
        assert csv_rows[1][7] == "us-west-2"
        assert csv_rows[1][9] == "FAIL"
        assert csv_rows[1][10] == "3"
        assert csv_rows[1][11] == "2"

        # Validate third row
        assert csv_rows[2][0] == str(rows[2]["id"])
        assert csv_rows[2][3] == "aws_foundational_security_aws"
        assert csv_rows[2][5] == "2.0"
        assert csv_rows[2][9] == "MANUAL"

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_null_values(
        self, mock_psycopg_connection, settings
    ):
        """Test COPY handles NULL/None values correctly in nullable fields."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        captured = {}

        def copy_side_effect(sql, file_obj):
            captured["sql"] = sql
            captured["data"] = file_obj.read()

        cursor.copy_expert.side_effect = copy_side_effect

        # Row with all nullable fields set to None/empty
        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "test_framework",
            "framework": "Test",
            "version": None,  # nullable
            "description": None,  # nullable
            "region": "",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 0,
            "failed_checks": 0,
            "total_checks": 0,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        csv_rows = list(csv.reader(StringIO(captured["data"])))
        assert len(csv_rows) == 1

        # Validate that None values are converted to empty strings in CSV
        assert csv_rows[0][5] == ""  # version
        assert csv_rows[0][6] == ""  # description

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_special_characters(
        self, mock_psycopg_connection, settings
    ):
        """Test COPY correctly escapes special characters in CSV."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        captured = {}

        def copy_side_effect(sql, file_obj):
            captured["sql"] = sql
            captured["data"] = file_obj.read()

        cursor.copy_expert.side_effect = copy_side_effect

        # Row with special characters that need escaping
        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": 'framework"with"quotes',
            "framework": "Framework,with,commas",
            "version": "1.0",
            "description": 'Description with "quotes", commas, and\nnewlines',
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        # Verify CSV was generated (csv module handles escaping automatically)
        csv_rows = list(csv.reader(StringIO(captured["data"])))
        assert len(csv_rows) == 1

        # Verify special characters are preserved after CSV parsing
        assert csv_rows[0][3] == 'framework"with"quotes'
        assert csv_rows[0][4] == "Framework,with,commas"
        assert "quotes" in csv_rows[0][6]
        assert "commas" in csv_rows[0][6]

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_missing_inserted_at(
        self, mock_psycopg_connection, settings
    ):
        """Test COPY uses current datetime when inserted_at is missing."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        captured = {}

        def copy_side_effect(sql, file_obj):
            captured["sql"] = sql
            captured["data"] = file_obj.read()

        cursor.copy_expert.side_effect = copy_side_effect

        # Row without inserted_at field
        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "test_framework",
            "framework": "Test",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
            # Note: inserted_at is intentionally missing
        }

        before_call = datetime.now(timezone.utc)
        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])
        after_call = datetime.now(timezone.utc)

        csv_rows = list(csv.reader(StringIO(captured["data"])))
        assert len(csv_rows) == 1

        # Verify inserted_at was auto-generated and is a valid ISO datetime
        inserted_at_str = csv_rows[0][2]
        inserted_at = datetime.fromisoformat(inserted_at_str)
        assert before_call <= inserted_at <= after_call

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_transaction_rollback_on_copy_error(
        self, mock_psycopg_connection, settings
    ):
        """Test transaction is rolled back when copy_expert fails."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        # Simulate copy_expert failure
        cursor.copy_expert.side_effect = Exception("COPY command failed")

        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "test",
            "framework": "Test",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            with pytest.raises(Exception, match="COPY command failed"):
                _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        # Verify rollback was called
        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_transaction_rollback_on_set_config_error(
        self, mock_psycopg_connection, settings
    ):
        """Test transaction is rolled back when SET_CONFIG fails."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        # Simulate cursor.execute failure
        cursor.execute.side_effect = Exception("SET prowler.tenant_id failed")

        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "test",
            "framework": "Test",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            with pytest.raises(Exception, match="SET prowler.tenant_id failed"):
                _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        # Verify rollback was called
        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_copy_compliance_requirement_rows_commit_on_success(
        self, mock_psycopg_connection, settings
    ):
        """Test transaction is committed on successful COPY."""
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        cursor.copy_expert.return_value = None  # Success

        row = {
            "id": uuid.uuid4(),
            "tenant_id": str(uuid.uuid4()),
            "compliance_id": "test",
            "framework": "Test",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        with patch.object(MainRouter, "admin_db", "admin"):
            _copy_compliance_requirement_rows(str(row["tenant_id"]), [row])

        # Verify commit was called and rollback was not
        connection.commit.assert_called_once()
        connection.rollback.assert_not_called()
        # Verify autocommit was disabled
        assert connection.autocommit is False

    @patch("tasks.jobs.scan._copy_compliance_requirement_rows")
    def test_persist_compliance_requirement_rows_success(self, mock_copy):
        """Test successful COPY path without fallback to ORM."""
        mock_copy.return_value = None  # Success, no exception

        tenant_id = str(uuid.uuid4())
        rows = [
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": datetime.now(timezone.utc),
                "compliance_id": "test",
                "framework": "Test",
                "version": "1.0",
                "description": "desc",
                "region": "us-east-1",
                "requirement_id": "req-1",
                "requirement_status": "PASS",
                "passed_checks": 1,
                "failed_checks": 0,
                "total_checks": 1,
                "scan_id": uuid.uuid4(),
            }
        ]

        _persist_compliance_requirement_rows(tenant_id, rows)

        # Verify COPY was called
        mock_copy.assert_called_once_with(tenant_id, rows)

    @patch("tasks.jobs.scan.logger")
    @patch("tasks.jobs.scan.ComplianceRequirementOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    @patch(
        "tasks.jobs.scan._copy_compliance_requirement_rows",
        side_effect=Exception("COPY failed"),
    )
    def test_persist_compliance_requirement_rows_fallback_logging(
        self, mock_copy, mock_rls_transaction, mock_bulk_create, mock_logger
    ):
        """Test logger.exception is called when COPY fails and fallback occurs."""
        tenant_id = str(uuid.uuid4())
        row = {
            "id": uuid.uuid4(),
            "tenant_id": tenant_id,
            "inserted_at": datetime.now(timezone.utc),
            "compliance_id": "test",
            "framework": "Test",
            "version": "1.0",
            "description": "desc",
            "region": "us-east-1",
            "requirement_id": "req-1",
            "requirement_status": "PASS",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
            "scan_id": uuid.uuid4(),
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _persist_compliance_requirement_rows(tenant_id, [row])

        # Verify logger.exception was called
        mock_logger.exception.assert_called_once()
        args, kwargs = mock_logger.exception.call_args
        assert "COPY bulk insert" in args[0]
        assert "falling back to ORM" in args[0]
        assert kwargs.get("exc_info") is not None

    @patch("tasks.jobs.scan.ComplianceRequirementOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    @patch(
        "tasks.jobs.scan._copy_compliance_requirement_rows",
        side_effect=Exception("copy failed"),
    )
    def test_persist_compliance_requirement_rows_fallback_multiple_rows(
        self, mock_copy, mock_rls_transaction, mock_bulk_create
    ):
        """Test ORM fallback with multiple rows."""
        tenant_id = str(uuid.uuid4())
        scan_id = uuid.uuid4()
        inserted_at = datetime.now(timezone.utc)

        rows = [
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": inserted_at,
                "compliance_id": "cisa_aws",
                "framework": "CISA",
                "version": "1.0",
                "description": "First requirement",
                "region": "us-east-1",
                "requirement_id": "req-1",
                "requirement_status": "PASS",
                "passed_checks": 5,
                "failed_checks": 0,
                "total_checks": 5,
                "scan_id": scan_id,
            },
            {
                "id": uuid.uuid4(),
                "tenant_id": tenant_id,
                "inserted_at": inserted_at,
                "compliance_id": "cisa_aws",
                "framework": "CISA",
                "version": "1.0",
                "description": "Second requirement",
                "region": "us-west-2",
                "requirement_id": "req-2",
                "requirement_status": "FAIL",
                "passed_checks": 2,
                "failed_checks": 3,
                "total_checks": 5,
                "scan_id": scan_id,
            },
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _persist_compliance_requirement_rows(tenant_id, rows)

        mock_copy.assert_called_once_with(tenant_id, rows)
        mock_rls_transaction.assert_called_once_with(tenant_id)
        mock_bulk_create.assert_called_once()

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 2
        assert kwargs["batch_size"] == 500

        # Validate first object
        assert objects[0].id == rows[0]["id"]
        assert objects[0].tenant_id == rows[0]["tenant_id"]
        assert objects[0].compliance_id == rows[0]["compliance_id"]
        assert objects[0].framework == rows[0]["framework"]
        assert objects[0].region == rows[0]["region"]
        assert objects[0].passed_checks == 5
        assert objects[0].failed_checks == 0

        # Validate second object
        assert objects[1].id == rows[1]["id"]
        assert objects[1].requirement_id == rows[1]["requirement_id"]
        assert objects[1].requirement_status == rows[1]["requirement_status"]
        assert objects[1].passed_checks == 2
        assert objects[1].failed_checks == 3

    @patch("tasks.jobs.scan.ComplianceRequirementOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    @patch(
        "tasks.jobs.scan._copy_compliance_requirement_rows",
        side_effect=Exception("copy failed"),
    )
    def test_persist_compliance_requirement_rows_fallback_all_fields(
        self, mock_copy, mock_rls_transaction, mock_bulk_create
    ):
        """Test ORM fallback correctly maps all fields from row dict to model."""
        tenant_id = str(uuid.uuid4())
        row_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        inserted_at = datetime.now(timezone.utc)

        row = {
            "id": row_id,
            "tenant_id": tenant_id,
            "inserted_at": inserted_at,
            "compliance_id": "aws_foundational_security_aws",
            "framework": "AWS-Foundational-Security-Best-Practices",
            "version": "2.0",
            "description": "Ensure MFA is enabled",
            "region": "eu-west-1",
            "requirement_id": "iam.1",
            "requirement_status": "FAIL",
            "passed_checks": 10,
            "failed_checks": 5,
            "total_checks": 15,
            "scan_id": scan_id,
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _persist_compliance_requirement_rows(tenant_id, [row])

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 1

        obj = objects[0]
        # Validate ALL fields are correctly mapped
        assert obj.id == row_id
        assert obj.tenant_id == tenant_id
        assert obj.inserted_at == inserted_at
        assert obj.compliance_id == "aws_foundational_security_aws"
        assert obj.framework == "AWS-Foundational-Security-Best-Practices"
        assert obj.version == "2.0"
        assert obj.description == "Ensure MFA is enabled"
        assert obj.region == "eu-west-1"
        assert obj.requirement_id == "iam.1"
        assert obj.requirement_status == "FAIL"
        assert obj.passed_checks == 10
        assert obj.failed_checks == 5
        assert obj.total_checks == 15
        assert obj.scan_id == scan_id


@pytest.mark.django_db
class TestCreateComplianceSummaries:
    """Test _create_compliance_summaries function."""

    @patch("tasks.jobs.scan.ComplianceOverviewSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_create_compliance_summaries_mixed_statuses(
        self, mock_rls_transaction, mock_bulk_create
    ):
        """Test creating summaries with mixed requirement statuses (PASS/FAIL/MANUAL)."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        # Simulate pre-computed requirement statuses
        requirement_statuses = {
            ("compliance1", "req1"): {
                "fail_count": 0,
                "pass_count": 5,
                "total_count": 5,
            },
            ("compliance1", "req2"): {
                "fail_count": 2,
                "pass_count": 3,
                "total_count": 5,
            },
            ("compliance1", "req3"): {
                "fail_count": 0,
                "pass_count": 3,
                "total_count": 5,
            },
            ("compliance2", "req1"): {
                "fail_count": 1,
                "pass_count": 0,
                "total_count": 5,
            },
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        mock_rls_transaction.assert_called_once_with(tenant_id)
        mock_bulk_create.assert_called_once()

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 2
        assert kwargs["batch_size"] == 500

        # Find compliance1 and compliance2 summaries
        comp1 = next(obj for obj in objects if obj.compliance_id == "compliance1")
        comp2 = next(obj for obj in objects if obj.compliance_id == "compliance2")

        # compliance1: req1=PASS, req2=FAIL (has fail_count), req3=MANUAL (pass < total)
        assert comp1.total_requirements == 3
        assert comp1.requirements_passed == 1
        assert comp1.requirements_failed == 1
        assert comp1.requirements_manual == 1

        # compliance2: req1=FAIL (has fail_count)
        assert comp2.total_requirements == 1
        assert comp2.requirements_passed == 0
        assert comp2.requirements_failed == 1
        assert comp2.requirements_manual == 0

    @patch("tasks.jobs.scan.ComplianceOverviewSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_create_compliance_summaries_empty_input(
        self, mock_rls_transaction, mock_bulk_create
    ):
        """Test with empty requirement_statuses dict - should not create any summaries."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        requirement_statuses = {}

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        # Should not call bulk_create with empty list
        mock_bulk_create.assert_not_called()

    @patch("tasks.jobs.scan.ComplianceOverviewSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_create_compliance_summaries_all_pass(
        self, mock_rls_transaction, mock_bulk_create
    ):
        """Test creating summaries when all requirements pass."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        requirement_statuses = {
            ("comp1", "req1"): {"fail_count": 0, "pass_count": 10, "total_count": 10},
            ("comp1", "req2"): {"fail_count": 0, "pass_count": 5, "total_count": 5},
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 1

        obj = objects[0]
        assert obj.compliance_id == "comp1"
        assert obj.total_requirements == 2
        assert obj.requirements_passed == 2
        assert obj.requirements_failed == 0
        assert obj.requirements_manual == 0

    @patch("tasks.jobs.scan.ComplianceOverviewSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_create_compliance_summaries_all_fail(
        self, mock_rls_transaction, mock_bulk_create
    ):
        """Test creating summaries when all requirements fail."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        requirement_statuses = {
            ("comp1", "req1"): {"fail_count": 3, "pass_count": 7, "total_count": 10},
            ("comp1", "req2"): {"fail_count": 1, "pass_count": 4, "total_count": 5},
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 1

        obj = objects[0]
        assert obj.compliance_id == "comp1"
        assert obj.total_requirements == 2
        assert obj.requirements_passed == 0
        assert obj.requirements_failed == 2
        assert obj.requirements_manual == 0

    @patch("tasks.jobs.scan.ComplianceOverviewSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_create_compliance_summaries_correct_aggregation(
        self, mock_rls_transaction, mock_bulk_create
    ):
        """Test that requirements are correctly aggregated to compliance level."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        requirement_statuses = {
            ("compliance_a", "req1"): {
                "fail_count": 0,
                "pass_count": 10,
                "total_count": 10,
            },
            ("compliance_a", "req2"): {
                "fail_count": 1,
                "pass_count": 9,
                "total_count": 10,
            },
            ("compliance_a", "req3"): {
                "fail_count": 0,
                "pass_count": 5,
                "total_count": 10,
            },
            ("compliance_b", "req1"): {
                "fail_count": 0,
                "pass_count": 8,
                "total_count": 8,
            },
        }

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert len(objects) == 2

        comp_a = next(obj for obj in objects if obj.compliance_id == "compliance_a")
        comp_b = next(obj for obj in objects if obj.compliance_id == "compliance_b")

        # compliance_a: req1=PASS, req2=FAIL, req3=MANUAL
        assert comp_a.total_requirements == 3
        assert comp_a.requirements_passed == 1
        assert comp_a.requirements_failed == 1
        assert comp_a.requirements_manual == 1

        # compliance_b: req1=PASS
        assert comp_b.total_requirements == 1
        assert comp_b.requirements_passed == 1
        assert comp_b.requirements_failed == 0
        assert comp_b.requirements_manual == 0


@pytest.mark.django_db
class TestNormalizedComplianceKey:
    """Test _normalized_compliance_key function."""

    def test_normalized_compliance_key_normal_strings(self):
        """Test normalization with normal framework and version strings."""
        result = _normalized_compliance_key("AWS-Foundational-Security", "2.0")
        assert result == "awsfoundationalsecurity20"

    def test_normalized_compliance_key_with_underscores(self):
        """Test normalization removes underscores."""
        result = _normalized_compliance_key("CIS_AWS_Foundations", "1_5_0")
        assert result == "cisawsfoundations150"

    def test_normalized_compliance_key_none_framework(self):
        """Test normalization with None framework."""
        result = _normalized_compliance_key(None, "1.0")
        assert result == "10"

    def test_normalized_compliance_key_none_version(self):
        """Test normalization with None version."""
        result = _normalized_compliance_key("AWS-Security", None)
        assert result == "awssecurity"

    def test_normalized_compliance_key_both_none(self):
        """Test normalization with both framework and version as None."""
        result = _normalized_compliance_key(None, None)
        assert result == ""

    def test_normalized_compliance_key_empty_strings(self):
        """Test normalization with empty strings."""
        result = _normalized_compliance_key("", "")
        assert result == ""

    def test_normalized_compliance_key_mixed_case(self):
        """Test normalization lowercases strings."""
        result = _normalized_compliance_key("AWS-FOUNDATIONAL", "V2.0")
        assert result == "awsfoundationalv20"

    def test_normalized_compliance_key_complex_pattern(self):
        """Test normalization with complex patterns."""
        result = _normalized_compliance_key("PCI-DSS_v3-2-1", "2023-Update")
        assert result == "pcidssv3212023update"


@pytest.mark.django_db
class TestAggregateFindings:
    """Test aggregate_findings function."""

    @patch("tasks.jobs.scan.ScanSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_creates_scan_summaries(
        self,
        mock_rls_transaction,
        mock_bulk_create,
        tenants_fixture,
        scans_fixture,
        findings_fixture,
    ):
        """Test that aggregate_findings creates ScanSummary records."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        aggregate_findings(str(tenant.id), str(scan.id))

        mock_rls_transaction.assert_called()
        mock_bulk_create.assert_called_once()

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]
        assert kwargs["batch_size"] == 3000
        # Should have created at least one summary
        assert len(objects) > 0

    @patch("tasks.jobs.scan.Finding.objects.filter")
    @patch("tasks.jobs.scan.ScanSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_excludes_muted_from_counts(
        self, mock_rls_transaction, mock_bulk_create, mock_findings_filter
    ):
        """Test that muted findings are excluded from fail/pass counts but counted separately."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        # Mock findings queryset
        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {
                "check_id": "check1",
                "resources__service": "s3",
                "severity": "high",
                "resources__region": "us-east-1",
                "fail": 5,
                "_pass": 10,
                "muted_count": 3,
                "total": 18,
                "new": 2,
                "changed": 1,
                "unchanged": 12,
                "fail_new": 1,
                "fail_changed": 0,
                "pass_new": 1,
                "pass_changed": 0,
                "muted_new": 0,
                "muted_changed": 1,
            }
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_findings(tenant_id, scan_id)

        mock_bulk_create.assert_called_once()
        args, kwargs = mock_bulk_create.call_args
        objects = args[0]

        summary = list(objects)[0]
        assert summary.fail == 5
        assert summary._pass == 10
        assert summary.muted == 3
        assert summary.total == 18

    @patch("tasks.jobs.scan.Finding.objects.filter")
    @patch("tasks.jobs.scan.ScanSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_computes_deltas_correctly(
        self, mock_rls_transaction, mock_bulk_create, mock_findings_filter
    ):
        """Test that delta counts (new, changed, unchanged) are computed correctly."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {
                "check_id": "check1",
                "resources__service": "ec2",
                "severity": "critical",
                "resources__region": "us-west-2",
                "fail": 8,
                "_pass": 12,
                "muted_count": 2,
                "total": 22,
                "new": 5,
                "changed": 3,
                "unchanged": 12,
                "fail_new": 3,
                "fail_changed": 2,
                "pass_new": 2,
                "pass_changed": 1,
                "muted_new": 1,
                "muted_changed": 0,
            }
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_findings(tenant_id, scan_id)

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]

        summary = list(objects)[0]
        assert summary.new == 5
        assert summary.changed == 3
        assert summary.unchanged == 12
        assert summary.fail_new == 3
        assert summary.fail_changed == 2
        assert summary.pass_new == 2
        assert summary.pass_changed == 1
        assert summary.muted_new == 1
        assert summary.muted_changed == 0

    @patch("tasks.jobs.scan.Finding.objects.filter")
    @patch("tasks.jobs.scan.ScanSummary.objects.bulk_create")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_groups_by_dimensions(
        self, mock_rls_transaction, mock_bulk_create, mock_findings_filter
    ):
        """Test that findings are grouped by check_id, service, severity, and region."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {
                "check_id": "check1",
                "resources__service": "s3",
                "severity": "high",
                "resources__region": "us-east-1",
                "fail": 5,
                "_pass": 10,
                "muted_count": 0,
                "total": 15,
                "new": 2,
                "changed": 1,
                "unchanged": 12,
                "fail_new": 1,
                "fail_changed": 0,
                "pass_new": 1,
                "pass_changed": 1,
                "muted_new": 0,
                "muted_changed": 0,
            },
            {
                "check_id": "check1",
                "resources__service": "s3",
                "severity": "high",
                "resources__region": "us-west-2",
                "fail": 3,
                "_pass": 7,
                "muted_count": 1,
                "total": 11,
                "new": 1,
                "changed": 0,
                "unchanged": 9,
                "fail_new": 1,
                "fail_changed": 0,
                "pass_new": 0,
                "pass_changed": 0,
                "muted_new": 0,
                "muted_changed": 1,
            },
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_findings(tenant_id, scan_id)

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]

        # Should create 2 summaries (different regions)
        assert len(list(objects)) == 2

        summaries = list(objects)
        assert all(s.check_id == "check1" for s in summaries)
        assert all(s.service == "s3" for s in summaries)
        assert all(s.severity == "high" for s in summaries)

        regions = {s.region for s in summaries}
        assert regions == {"us-east-1", "us-west-2"}


@pytest.mark.django_db
class TestAggregateFindingsByRegion:
    """Test _aggregate_findings_by_region function."""

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_returns_correct_structure(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test function returns correct data structure."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        # Mock findings with resources
        mock_finding1 = MagicMock()
        mock_finding1.check_id = "check1"
        mock_finding1.status = "FAIL"
        mock_finding1.compliance = {modeled_threatscore_compliance_id: ["req1", "req2"]}

        mock_resource1 = MagicMock()
        mock_resource1.region = "us-east-1"
        mock_finding1.small_resources = [mock_resource1]

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = [mock_finding1]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        check_status_by_region, findings_count_by_compliance = (
            _aggregate_findings_by_region(
                tenant_id, scan_id, modeled_threatscore_compliance_id
            )
        )

        # Verify structure of check_status_by_region
        assert isinstance(check_status_by_region, dict)
        assert "us-east-1" in check_status_by_region
        assert "check1" in check_status_by_region["us-east-1"]
        assert check_status_by_region["us-east-1"]["check1"] == "FAIL"

        # Verify structure of findings_count_by_compliance
        assert isinstance(findings_count_by_compliance, dict)

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_fail_status_priority(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test that FAIL status takes priority over other statuses."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        # First finding with PASS status
        mock_finding1 = MagicMock()
        mock_finding1.check_id = "check1"
        mock_finding1.status = "PASS"
        mock_finding1.compliance = {}
        mock_resource1 = MagicMock()
        mock_resource1.region = "us-east-1"
        mock_finding1.small_resources = [mock_resource1]

        # Second finding with FAIL status for same check/region
        mock_finding2 = MagicMock()
        mock_finding2.check_id = "check1"
        mock_finding2.status = "FAIL"
        mock_finding2.compliance = {}
        mock_resource2 = MagicMock()
        mock_resource2.region = "us-east-1"
        mock_finding2.small_resources = [mock_resource2]

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = [mock_finding1, mock_finding2]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        check_status_by_region, _ = _aggregate_findings_by_region(
            tenant_id, scan_id, modeled_threatscore_compliance_id
        )

        # FAIL should override PASS
        assert check_status_by_region["us-east-1"]["check1"] == "FAIL"

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_filters_muted(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test that muted findings are filtered out (muted=False in query)."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = []

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        _aggregate_findings_by_region(
            tenant_id, scan_id, modeled_threatscore_compliance_id
        )

        # Verify filter was called with muted=False
        mock_findings_filter.assert_called_once_with(
            tenant_id=tenant_id,
            scan_id=scan_id,
            muted=False,
            status__in=["PASS", "FAIL"],
        )

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_processes_compliance_counts(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test that ThreatScore compliance counts are processed correctly."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        # Finding with PASS status
        mock_finding1 = MagicMock()
        mock_finding1.check_id = "check1"
        mock_finding1.status = "PASS"
        mock_finding1.compliance = {modeled_threatscore_compliance_id: ["req1"]}
        mock_resource1 = MagicMock()
        mock_resource1.region = "us-east-1"
        mock_finding1.small_resources = [mock_resource1]

        # Finding with FAIL status
        mock_finding2 = MagicMock()
        mock_finding2.check_id = "check2"
        mock_finding2.status = "FAIL"
        mock_finding2.compliance = {modeled_threatscore_compliance_id: ["req1"]}
        mock_resource2 = MagicMock()
        mock_resource2.region = "us-east-1"
        mock_finding2.small_resources = [mock_resource2]

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = [mock_finding1, mock_finding2]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        _, findings_count_by_compliance = _aggregate_findings_by_region(
            tenant_id, scan_id, modeled_threatscore_compliance_id
        )

        # Verify compliance counts
        normalized_id = re.sub(
            r"[^a-z0-9]", "", modeled_threatscore_compliance_id.lower()
        )
        assert "us-east-1" in findings_count_by_compliance
        assert normalized_id in findings_count_by_compliance["us-east-1"]
        assert "req1" in findings_count_by_compliance["us-east-1"][normalized_id]

        req_stats = findings_count_by_compliance["us-east-1"][normalized_id]["req1"]
        assert req_stats["total"] == 2
        assert req_stats["pass"] == 1

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_multiple_regions(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test aggregation across multiple regions."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        # Finding in us-east-1
        mock_finding1 = MagicMock()
        mock_finding1.check_id = "check1"
        mock_finding1.status = "FAIL"
        mock_finding1.compliance = {}
        mock_resource1 = MagicMock()
        mock_resource1.region = "us-east-1"
        mock_finding1.small_resources = [mock_resource1]

        # Finding in us-west-2
        mock_finding2 = MagicMock()
        mock_finding2.check_id = "check1"
        mock_finding2.status = "PASS"
        mock_finding2.compliance = {}
        mock_resource2 = MagicMock()
        mock_resource2.region = "us-west-2"
        mock_finding2.small_resources = [mock_resource2]

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = [mock_finding1, mock_finding2]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        check_status_by_region, _ = _aggregate_findings_by_region(
            tenant_id, scan_id, modeled_threatscore_compliance_id
        )

        # Verify both regions are present with correct statuses
        assert "us-east-1" in check_status_by_region
        assert "us-west-2" in check_status_by_region
        assert check_status_by_region["us-east-1"]["check1"] == "FAIL"
        assert check_status_by_region["us-west-2"]["check1"] == "PASS"

    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_findings_by_region_empty_findings(
        self, mock_rls_transaction, mock_findings_filter
    ):
        """Test with no findings - should return empty dicts."""
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        mock_queryset = MagicMock()
        mock_queryset.only.return_value = mock_queryset
        mock_queryset.prefetch_related.return_value = []

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        check_status_by_region, findings_count_by_compliance = (
            _aggregate_findings_by_region(
                tenant_id, scan_id, modeled_threatscore_compliance_id
            )
        )

        assert check_status_by_region == {}
        assert findings_count_by_compliance == {}


@pytest.mark.django_db
class TestAggregateAttackSurface:
    """Test aggregate_attack_surface function and related caching."""

    def setup_method(self):
        """Clear cache before each test."""
        _ATTACK_SURFACE_MAPPING_CACHE.clear()

    def teardown_method(self):
        """Clear cache after each test."""
        _ATTACK_SURFACE_MAPPING_CACHE.clear()

    @patch("tasks.jobs.scan.CheckMetadata.list")
    def test_get_attack_surface_mapping_caches_result(self, mock_check_metadata_list):
        """Test that _get_attack_surface_mapping_from_provider caches results."""
        mock_check_metadata_list.return_value = {"check_internet_exposed_1"}

        # First call should hit CheckMetadata.list
        result1 = _get_attack_surface_mapping_from_provider("aws")
        assert mock_check_metadata_list.call_count == 2  # internet-exposed, secrets

        # Second call should use cache
        result2 = _get_attack_surface_mapping_from_provider("aws")
        assert mock_check_metadata_list.call_count == 2  # No additional calls

        assert result1 is result2
        assert "aws" in _ATTACK_SURFACE_MAPPING_CACHE

    @patch("tasks.jobs.scan.CheckMetadata.list")
    def test_get_attack_surface_mapping_different_providers(
        self, mock_check_metadata_list
    ):
        """Test caching works independently for different providers."""
        mock_check_metadata_list.return_value = {"check_1"}

        _get_attack_surface_mapping_from_provider("aws")
        aws_call_count = mock_check_metadata_list.call_count

        _get_attack_surface_mapping_from_provider("gcp")
        gcp_call_count = mock_check_metadata_list.call_count

        # Both providers should have made calls
        assert gcp_call_count > aws_call_count
        assert "aws" in _ATTACK_SURFACE_MAPPING_CACHE
        assert "gcp" in _ATTACK_SURFACE_MAPPING_CACHE

    @patch("tasks.jobs.scan.CheckMetadata.list")
    def test_get_attack_surface_mapping_returns_hardcoded_checks(
        self, mock_check_metadata_list
    ):
        """Test that hardcoded check IDs are returned for privilege-escalation and ec2-imdsv1."""
        mock_check_metadata_list.return_value = set()

        result = _get_attack_surface_mapping_from_provider("aws")

        # Hardcoded checks should be present
        assert (
            "iam_policy_allows_privilege_escalation" in result["privilege-escalation"]
        )
        assert (
            "iam_inline_policy_allows_privilege_escalation"
            in result["privilege-escalation"]
        )
        assert "ec2_instance_imdsv2_enabled" in result["ec2-imdsv1"]

    @patch("tasks.jobs.scan.AttackSurfaceOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan._get_attack_surface_mapping_from_provider")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_attack_surface_creates_overview_records(
        self,
        mock_rls_transaction,
        mock_get_mapping,
        mock_findings_filter,
        mock_bulk_create,
        tenants_fixture,
        scans_fixture,
    ):
        """Test that aggregate_attack_surface creates AttackSurfaceOverview records."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        scan.provider.provider = "aws"
        scan.provider.save()

        mock_get_mapping.return_value = {
            "internet-exposed": {"check_internet_1", "check_internet_2"},
            "secrets": {"check_secrets_1"},
            "privilege-escalation": {"check_privesc_1"},
            "ec2-imdsv1": {"check_imdsv1_1"},
        }

        # Mock findings aggregation
        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {"check_id": "check_internet_1", "total": 10, "failed": 3, "muted": 1},
            {"check_id": "check_secrets_1", "total": 5, "failed": 2, "muted": 0},
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_attack_surface(str(tenant.id), str(scan.id))

        mock_bulk_create.assert_called_once()
        args, kwargs = mock_bulk_create.call_args
        objects = args[0]

        # Should create records for internet-exposed and secrets (the ones with findings)
        assert len(objects) == 2
        assert kwargs["batch_size"] == 500

    @patch("tasks.jobs.scan.AttackSurfaceOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan._get_attack_surface_mapping_from_provider")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_attack_surface_skips_unsupported_provider(
        self,
        mock_rls_transaction,
        mock_get_mapping,
        mock_findings_filter,
        mock_bulk_create,
        tenants_fixture,
        scans_fixture,
    ):
        """Test that ec2-imdsv1 is skipped for non-AWS providers."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        scan.provider.provider = "gcp"
        scan.provider.uid = "gcp-test-project-id"
        scan.provider.save()

        mock_get_mapping.return_value = {
            "internet-exposed": {"check_internet_1"},
            "secrets": {"check_secrets_1"},
            "privilege-escalation": set(),  # Not supported for GCP
            "ec2-imdsv1": {"check_imdsv1_1"},  # Should be skipped for GCP
        }

        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {"check_id": "check_internet_1", "total": 5, "failed": 1, "muted": 0},
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_attack_surface(str(tenant.id), str(scan.id))

        # ec2-imdsv1 check_ids should not be in the filter
        filter_call = mock_findings_filter.call_args
        check_ids_in_filter = filter_call[1]["check_id__in"]
        assert "check_imdsv1_1" not in check_ids_in_filter

    @patch("tasks.jobs.scan.AttackSurfaceOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan._get_attack_surface_mapping_from_provider")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_attack_surface_no_findings(
        self,
        mock_rls_transaction,
        mock_get_mapping,
        mock_findings_filter,
        mock_bulk_create,
        tenants_fixture,
        scans_fixture,
    ):
        """Test that no records are created when there are no findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        mock_get_mapping.return_value = {
            "internet-exposed": {"check_1"},
            "secrets": {"check_2"},
            "privilege-escalation": set(),
            "ec2-imdsv1": set(),
        }

        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = []  # No findings

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_attack_surface(str(tenant.id), str(scan.id))

        mock_bulk_create.assert_not_called()

    @patch("tasks.jobs.scan.AttackSurfaceOverview.objects.bulk_create")
    @patch("tasks.jobs.scan.Finding.all_objects.filter")
    @patch("tasks.jobs.scan._get_attack_surface_mapping_from_provider")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_attack_surface_aggregates_counts_correctly(
        self,
        mock_rls_transaction,
        mock_get_mapping,
        mock_findings_filter,
        mock_bulk_create,
        tenants_fixture,
        scans_fixture,
    ):
        """Test that counts from multiple check_ids are aggregated per attack surface type."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        scan.provider.provider = "aws"
        scan.provider.save()

        mock_get_mapping.return_value = {
            "internet-exposed": {"check_internet_1", "check_internet_2"},
            "secrets": set(),
            "privilege-escalation": set(),
            "ec2-imdsv1": set(),
        }

        mock_queryset = MagicMock()
        mock_queryset.values.return_value = mock_queryset
        mock_queryset.annotate.return_value = [
            {"check_id": "check_internet_1", "total": 10, "failed": 3, "muted": 1},
            {"check_id": "check_internet_2", "total": 5, "failed": 2, "muted": 0},
        ]

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx
        mock_findings_filter.return_value = mock_queryset

        aggregate_attack_surface(str(tenant.id), str(scan.id))

        args, kwargs = mock_bulk_create.call_args
        objects = args[0]

        assert len(objects) == 1
        overview = objects[0]
        assert overview.attack_surface_type == "internet-exposed"
        assert overview.total_findings == 15  # 10 + 5
        assert overview.failed_findings == 5  # 3 + 2
        assert overview.muted_failed_findings == 1  # 1 + 0

    @patch("tasks.jobs.scan.Scan.all_objects.select_related")
    @patch("tasks.jobs.scan.rls_transaction")
    def test_aggregate_attack_surface_uses_select_related(
        self, mock_rls_transaction, mock_select_related, tenants_fixture, scans_fixture
    ):
        """Test that select_related is used to avoid N+1 query."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        mock_scan = MagicMock()
        mock_scan.provider.provider = "aws"

        mock_select_related.return_value.get.return_value = mock_scan

        ctx = MagicMock()
        ctx.__enter__.return_value = None
        ctx.__exit__.return_value = False
        mock_rls_transaction.return_value = ctx

        with patch(
            "tasks.jobs.scan._get_attack_surface_mapping_from_provider"
        ) as mock_map:
            mock_map.return_value = {}

            aggregate_attack_surface(str(tenant.id), str(scan.id))

        mock_select_related.assert_called_once_with("provider")


class TestAggregateCategoryCounts:
    """Test aggregate_category_counts helper function."""

    def test_aggregate_category_counts_basic(self):
        """Test basic category counting for a non-muted PASS finding."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["security", "iam"],
            severity="high",
            status="PASS",
            delta=None,
            muted=False,
            cache=cache,
        )

        assert ("security", "high") in cache
        assert ("iam", "high") in cache
        assert cache[("security", "high")] == {"total": 1, "failed": 0, "new_failed": 0}
        assert cache[("iam", "high")] == {"total": 1, "failed": 0, "new_failed": 0}

    def test_aggregate_category_counts_fail_not_muted(self):
        """Test category counting for a non-muted FAIL finding."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["security"],
            severity="critical",
            status="FAIL",
            delta=None,
            muted=False,
            cache=cache,
        )

        assert cache[("security", "critical")] == {
            "total": 1,
            "failed": 1,
            "new_failed": 0,
        }

    def test_aggregate_category_counts_new_fail(self):
        """Test category counting for a new FAIL finding (delta='new')."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["gen-ai"],
            severity="high",
            status="FAIL",
            delta="new",
            muted=False,
            cache=cache,
        )

        assert cache[("gen-ai", "high")] == {"total": 1, "failed": 1, "new_failed": 1}

    def test_aggregate_category_counts_muted_finding(self):
        """Test that muted findings are excluded from all counts."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["security"],
            severity="high",
            status="FAIL",
            delta="new",
            muted=True,
            cache=cache,
        )

        assert cache[("security", "high")] == {"total": 0, "failed": 0, "new_failed": 0}

    def test_aggregate_category_counts_accumulates(self):
        """Test that multiple calls accumulate counts."""
        cache: dict[tuple[str, str], dict[str, int]] = {}

        # First finding: PASS
        aggregate_category_counts(
            categories=["security"],
            severity="high",
            status="PASS",
            delta=None,
            muted=False,
            cache=cache,
        )

        # Second finding: FAIL (new)
        aggregate_category_counts(
            categories=["security"],
            severity="high",
            status="FAIL",
            delta="new",
            muted=False,
            cache=cache,
        )

        # Third finding: FAIL (changed)
        aggregate_category_counts(
            categories=["security"],
            severity="high",
            status="FAIL",
            delta="changed",
            muted=False,
            cache=cache,
        )

        assert cache[("security", "high")] == {"total": 3, "failed": 2, "new_failed": 1}

    def test_aggregate_category_counts_empty_categories(self):
        """Test with empty categories list."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=[],
            severity="high",
            status="FAIL",
            delta="new",
            muted=False,
            cache=cache,
        )

        assert cache == {}

    def test_aggregate_category_counts_changed_delta(self):
        """Test that changed delta increments failed but not new_failed."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["iam"],
            severity="medium",
            status="FAIL",
            delta="changed",
            muted=False,
            cache=cache,
        )

        assert cache[("iam", "medium")] == {"total": 1, "failed": 1, "new_failed": 0}

    def test_aggregate_category_counts_multiple_categories_single_finding(self):
        """Test single finding with multiple categories."""
        cache: dict[tuple[str, str], dict[str, int]] = {}
        aggregate_category_counts(
            categories=["security", "compliance", "data-protection"],
            severity="low",
            status="FAIL",
            delta="new",
            muted=False,
            cache=cache,
        )

        assert len(cache) == 3
        for cat in ["security", "compliance", "data-protection"]:
            assert cache[(cat, "low")] == {"total": 1, "failed": 1, "new_failed": 1}


@pytest.mark.django_db
class TestUpdateProviderComplianceScores:
    @patch("tasks.jobs.scan.psycopg_connection")
    def test_update_provider_compliance_scores_basic(
        self,
        mock_psycopg_connection,
        tenants_fixture,
        scans_fixture,
        settings,
    ):
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        tenant_id = str(tenant.id)
        scan_id = str(scan.id)

        scan.state = StateChoices.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.save()

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

        cursor.rowcount = 2

        result = update_provider_compliance_scores(tenant_id, scan_id)

        assert result["status"] == "completed"
        assert result["upserted"] == 2
        assert cursor.execute.call_count >= 3
        connection.commit.assert_called_once()

    def test_update_provider_compliance_scores_skips_incomplete_scan(
        self, tenants_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[1]
        tenant_id = str(tenant.id)
        scan_id = str(scan.id)

        scan.state = StateChoices.AVAILABLE
        scan.completed_at = None
        scan.save()

        result = update_provider_compliance_scores(tenant_id, scan_id)

        assert result["status"] == "skipped"
        assert result["reason"] == "scan not completed"

    def test_update_provider_compliance_scores_skips_no_completed_at(
        self, tenants_fixture, scans_fixture
    ):
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        tenant_id = str(tenant.id)
        scan_id = str(scan.id)

        scan.state = StateChoices.COMPLETED
        scan.completed_at = None
        scan.save()

        result = update_provider_compliance_scores(tenant_id, scan_id)

        assert result["status"] == "skipped"
        assert result["reason"] == "no completed_at"

    @patch("tasks.jobs.scan.psycopg_connection")
    def test_update_provider_compliance_scores_executes_sql_queries(
        self,
        mock_psycopg_connection,
        tenants_fixture,
        providers_fixture,
        scans_fixture,
        settings,
    ):
        settings.DATABASES.setdefault("admin", settings.DATABASES["default"])
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        tenant_id = str(tenant.id)
        scan_id = str(scan.id)

        scan.state = StateChoices.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.save()

        connection = MagicMock()
        cursor = MagicMock()
        cursor_context = MagicMock()
        cursor_context.__enter__.return_value = cursor
        cursor_context.__exit__.return_value = False
        connection.cursor.return_value = cursor_context
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False

        context_manager = MagicMock()
        context_manager.__enter__.return_value = connection
        context_manager.__exit__.return_value = False
        mock_psycopg_connection.return_value = context_manager

        cursor.rowcount = 1
        cursor.fetchall.side_effect = [[("aws_cis_2.0",)], []]

        result = update_provider_compliance_scores(tenant_id, scan_id)

        assert result["status"] == "completed"

        calls = [str(c) for c in cursor.execute.call_args_list]
        assert any("provider_compliance_scores" in c for c in calls)
        assert any("tenant_compliance_summaries" in c for c in calls)
        assert any("pg_advisory_xact_lock" in c for c in calls)
