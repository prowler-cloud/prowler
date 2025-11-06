import csv
import json
import uuid
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.scan import (
    _copy_compliance_requirement_rows,
    _create_finding_delta,
    _persist_compliance_requirement_rows,
    _store_resources,
    create_compliance_requirements,
    perform_prowler_scan,
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
class TestCreateComplianceRequirements:
    def test_create_compliance_requirements_success(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
        resources_fixture,
    ):
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "cis_1.4_aws": {
                    "framework": "CIS AWS Foundations Benchmark",
                    "version": "1.4.0",
                    "requirements": {
                        "1.1": {
                            "description": "Ensure root access key does not exist",
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
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
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
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
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
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
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
        self, tenants_fixture, scans_fixture, providers_fixture, findings_fixture
    ):
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch(
                "tasks.jobs.scan.generate_scan_compliance"
            ) as mock_generate_compliance,
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "cis_1.4_aws": {
                    "framework": "CIS AWS Foundations Benchmark",
                    "version": "1.4.0",
                    "requirements": {
                        "1.1": {
                            "description": "Test requirement",
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

            assert mock_generate_compliance.call_count == 1

    def test_create_compliance_requirements_multiple_regions(
        self,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
        findings_fixture,
    ):
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
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
        with (
            patch(
                "tasks.jobs.scan.PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE"
            ) as mock_compliance_template,
            patch("tasks.jobs.scan.generate_scan_compliance"),
        ):
            tenant_id = str(tenants_fixture[0].id)
            scan_id = str(scans_fixture[0].id)

            mock_compliance_template.__getitem__.return_value = {
                "test_compliance": {
                    "framework": "Test Framework",
                    "version": "1.0",
                    "requirements": {
                        "req_1": {
                            "description": "Test Requirement 1",
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
