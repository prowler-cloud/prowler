import uuid
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.scan import (
    _create_finding_delta,
    _store_resources,
    perform_prowler_scan,
)

from api.models import (
    Finding,
    Provider,
    Resource,
    Severity,
    StateChoices,
    StatusChoices,
)


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
            finding.raw = {}

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

        assert scan_resource.tenant == tenant
        assert scan_resource.uid == finding.resource_uid
        assert scan_resource.region == finding.region
        assert scan_resource.service == finding.service_name
        assert scan_resource.type == finding.resource_type
        assert scan_resource.name == finding.resource_name

        # Assert that the resource tags have been created and associated
        tags = scan_resource.tags.all()
        assert tags.count() == 2
        tag_keys = {tag.key for tag in tags}
        tag_values = {tag.value for tag in tags}
        assert tag_keys == set(finding.resource_tags.keys())
        assert tag_values == set(finding.resource_tags.values())

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
        tag_instance = MagicMock()
        mock_get_or_create_tag.return_value = (tag_instance, True)

        resource, resource_uid_tuple = _store_resources(
            finding, tenant_id, provider_instance
        )

        mock_get_or_create_resource.assert_called_once_with(
            tenant_id=tenant_id,
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
            finding, tenant_id, provider_instance
        )

        mock_get_or_create_resource.assert_called_once_with(
            tenant_id=tenant_id,
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
            finding, tenant_id, provider_instance
        )

        mock_get_or_create_tag.assert_any_call(
            tenant_id=tenant_id, key="tag1", value="value1"
        )
        mock_get_or_create_tag.assert_any_call(
            tenant_id=tenant_id, key="tag2", value="value2"
        )
        resource_instance.upsert_or_delete_tags.assert_called_once()
        tags_passed = resource_instance.upsert_or_delete_tags.call_args[1]["tags"]
        assert tag_instance_1 in tags_passed
        assert tag_instance_2 in tags_passed

        assert resource == resource_instance
        assert resource_uid_tuple == (resource_instance.uid, resource_instance.region)


# TODO Add tests for aggregations
