import json
import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.scan import (
    _create_finding_delta,
    _store_resources,
    create_compliance_requirements,
    perform_prowler_scan,
)
from tasks.utils import CustomEncoder

from api.exceptions import ProviderConnectionError
from api.models import Finding, Provider, Resource, Scan, StateChoices, StatusChoices
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
