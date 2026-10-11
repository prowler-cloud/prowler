from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from api.db_utils import rls_transaction
from api.filters import ResourceFilter
from api.models import (
    Finding,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    Role,
    RoleProviderGroupRelationship,
    Scan,
    StateChoices,
    StatusChoices,
)
from django.urls import reverse


def create_scan(provider):
    return Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        state=StateChoices.COMPLETED,
        trigger=Scan.TriggerChoices.MANUAL,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )


def create_resource(provider):
    return Resource.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        uid=str(uuid4()),
        name="Scan resource",
        service="ec2",
        region="us-east-1",
        type="instance",
    )


def map_resource(scan, resource):
    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        scan=scan,
        uid=str(uuid4()),
        check_id="test_check",
        status=StatusChoices.PASS,
        severity="low",
        impact="low",
    )
    finding.add_resources([resource])
    return finding


def summarize_resource(scan, resource, tenant_id=None):
    return ResourceScanSummary.objects.create(
        tenant_id=tenant_id or scan.tenant_id,
        scan_id=scan.id,
        resource_id=resource.id,
        service=resource.service,
        region=resource.region,
        resource_type=resource.type,
    )


def assert_resources(client, filters, resources):
    response = client.get(reverse("resource-list"), filters)
    assert response.status_code == 200
    data = response.json()["data"]
    assert {item["id"] for item in data} == {str(resource.id) for resource in resources}
    assert len(data) == len(resources)


@pytest.mark.django_db
class TestResourceScanFilters:
    def test_single_scan_excludes_other_resources_on_same_provider(
        self, authenticated_client, aws_provider
    ):
        scan, other_scan = create_scan(aws_provider), create_scan(aws_provider)
        resource, other_resource = (
            create_resource(aws_provider),
            create_resource(aws_provider),
        )
        map_resource(scan, resource)
        map_resource(other_scan, other_resource)

        response = authenticated_client.get(
            reverse("resource-list"), {"filter[scan]": scan.id}
        )

        assert response.status_code == 200
        assert [item["id"] for item in response.json()["data"]] == [str(resource.id)]
        assert_resources(
            authenticated_client, {"filter[scan]": str(other_scan.id)}, [other_resource]
        )

    @pytest.mark.parametrize("filter_name", ["filter[scan]", "filter[scan__in]"])
    @pytest.mark.parametrize("membership", ["mapping", "summary", "partial"])
    def test_membership_sources_and_duplicate_findings(
        self, authenticated_client, aws_provider, filter_name, membership
    ):
        scan = create_scan(aws_provider)
        first, second, nonmember = [create_resource(aws_provider) for _ in range(3)]
        if membership in ("summary", "partial"):
            summarize_resource(scan, first)
        if membership == "summary":
            summarize_resource(scan, second)
        else:
            map_resource(scan, first)
            map_resource(scan, first)
            map_resource(scan, second)

        assert_resources(
            authenticated_client, {filter_name: str(scan.id)}, [first, second]
        )

    def test_multiple_scans_include_shared_resources_once(
        self, authenticated_client, aws_provider
    ):
        first_scan, second_scan, excluded_scan = [
            create_scan(aws_provider) for _ in range(3)
        ]
        first, shared, second, excluded = [
            create_resource(aws_provider) for _ in range(4)
        ]
        map_resource(first_scan, first)
        map_resource(first_scan, shared)
        map_resource(first_scan, shared)
        map_resource(second_scan, shared)
        summarize_resource(second_scan, shared)
        summarize_resource(second_scan, second)
        map_resource(excluded_scan, excluded)

        assert_resources(
            authenticated_client,
            {"filter[scan__in]": f"{first_scan.id},{second_scan.id}"},
            [first, shared, second],
        )

    @pytest.mark.parametrize("filter_name", ["filter[scan]", "filter[scan__in]"])
    def test_unknown_scan_excludes_orphan_summary(
        self, authenticated_client, aws_provider, filter_name
    ):
        resource = create_resource(aws_provider)
        unknown_scan = SimpleNamespace(id=uuid4(), tenant_id=aws_provider.tenant_id)
        summarize_resource(unknown_scan, resource)

        assert_resources(authenticated_client, {filter_name: str(unknown_scan.id)}, [])

    @pytest.mark.parametrize("membership", ["mapping", "summary"])
    def test_membership_rows_from_other_tenant_are_excluded(
        self, authenticated_client, aws_provider, tenants_fixture, membership
    ):
        scan = create_scan(aws_provider)
        resource = create_resource(aws_provider)
        other_tenant = tenants_fixture[2]
        if membership == "summary":
            summarize_resource(scan, resource, tenant_id=other_tenant.id)
        else:
            finding = map_resource(scan, resource)
            ResourceFindingMapping.objects.filter(finding=finding).update(
                tenant_id=other_tenant.id
            )

        assert_resources(authenticated_client, {"filter[scan]": str(scan.id)}, [])

    def test_foreign_scan_does_not_expose_local_resource_summary(
        self, authenticated_client, aws_provider, tenants_fixture
    ):
        other_tenant = tenants_fixture[2]
        other_provider = Provider.objects.create(
            tenant_id=other_tenant.id, provider="aws", uid="111122223333"
        )
        foreign_scan = create_scan(other_provider)
        foreign_resource = create_resource(other_provider)
        map_resource(foreign_scan, foreign_resource)
        summarize_resource(foreign_scan, foreign_resource)
        local_resource = create_resource(aws_provider)
        summarize_resource(
            foreign_scan, local_resource, tenant_id=aws_provider.tenant_id
        )

        assert_resources(
            authenticated_client, {"filter[scan]": str(foreign_scan.id)}, []
        )

    @pytest.mark.parametrize("membership", ["mapping", "summary"])
    def test_provider_group_visibility_is_preserved(
        self, authenticated_client, aws_provider_pair, membership
    ):
        visible_provider, hidden_provider = aws_provider_pair
        visible_scan, hidden_scan = (
            create_scan(visible_provider),
            create_scan(hidden_provider),
        )
        visible, hidden = (
            create_resource(visible_provider),
            create_resource(hidden_provider),
        )
        add_membership = map_resource if membership == "mapping" else summarize_resource
        add_membership(visible_scan, visible)
        add_membership(hidden_scan, hidden)
        tenant_id = visible_provider.tenant_id
        role = Role.objects.get(tenant_id=tenant_id, name="admin")
        role.unlimited_visibility = False
        role.save(update_fields=["unlimited_visibility"])
        group = ProviderGroup.objects.create(
            tenant_id=tenant_id, name="Visible providers"
        )
        ProviderGroupMembership.objects.create(
            tenant_id=tenant_id, provider=visible_provider, provider_group=group
        )
        RoleProviderGroupRelationship.objects.create(
            tenant_id=tenant_id, role=role, provider_group=group
        )

        assert_resources(
            authenticated_client,
            {"filter[scan__in]": f"{visible_scan.id},{hidden_scan.id}"},
            [visible],
        )
        assert_resources(
            authenticated_client, {"filter[scan]": str(hidden_scan.id)}, []
        )

    def test_membership_filter_is_lazy_and_uses_one_query(
        self, aws_provider, django_assert_num_queries
    ):
        scan = create_scan(aws_provider)
        resource = create_resource(aws_provider)
        map_resource(scan, resource)
        summarize_resource(scan, resource)
        request = SimpleNamespace(tenant_id=aws_provider.tenant_id)
        with rls_transaction(aws_provider.tenant_id):
            with django_assert_num_queries(0):
                queryset = ResourceFilter(
                    {"scan": str(scan.id)},
                    queryset=Resource.objects.filter(tenant_id=aws_provider.tenant_id),
                    request=request,
                ).qs
            with django_assert_num_queries(1):
                assert list(queryset.values_list("id", flat=True)) == [resource.id]

    @pytest.mark.parametrize("filter_name", ["filter[scan]", "filter[scan__in]"])
    @pytest.mark.parametrize("membership", ["mapping", "summary"])
    def test_retained_membership_after_provider_soft_deletion(
        self, authenticated_client, aws_provider, filter_name, membership
    ):
        scan = create_scan(aws_provider)
        resource = create_resource(aws_provider)
        add_membership = map_resource if membership == "mapping" else summarize_resource
        add_membership(scan, resource)
        aws_provider.is_deleted = True
        aws_provider.save(update_fields=["is_deleted"])

        assert_resources(authenticated_client, {filter_name: str(scan.id)}, [resource])

    @pytest.mark.parametrize("filter_name", ["filter[scan]", "filter[scan__in]"])
    @pytest.mark.parametrize("membership", ["mapping", "summary"])
    def test_limited_visibility_excludes_soft_deleted_provider_resources(
        self, authenticated_client, aws_provider, filter_name, membership
    ):
        scan = create_scan(aws_provider)
        resource = create_resource(aws_provider)
        add_membership = map_resource if membership == "mapping" else summarize_resource
        add_membership(scan, resource)
        tenant_id = aws_provider.tenant_id
        role = Role.objects.get(tenant_id=tenant_id, name="admin")
        role.unlimited_visibility = False
        role.save(update_fields=["unlimited_visibility"])
        group = ProviderGroup.objects.create(
            tenant_id=tenant_id, name="Visible providers"
        )
        ProviderGroupMembership.objects.create(
            tenant_id=tenant_id, provider=aws_provider, provider_group=group
        )
        RoleProviderGroupRelationship.objects.create(
            tenant_id=tenant_id, role=role, provider_group=group
        )
        date_filter = {"filter[updated_at]": resource.updated_at.date().isoformat()}
        scan_filter = {filter_name: str(scan.id)}

        assert_resources(authenticated_client, date_filter, [resource])
        assert_resources(authenticated_client, scan_filter, [resource])

        aws_provider.is_deleted = True
        aws_provider.save(update_fields=["is_deleted"])

        assert_resources(authenticated_client, date_filter, [])
        assert_resources(authenticated_client, scan_filter, [])
