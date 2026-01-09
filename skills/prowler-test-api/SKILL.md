---
name: prowler-test-api
description: >
  Testing patterns for Prowler API: ViewSets, Celery tasks, RLS isolation, RBAC.
  Trigger: When writing tests for api/ - viewsets, serializers, tasks, models.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
---

## Related Skills

- `pytest` - Generic pytest patterns
- `prowler-api` - API implementation patterns

---

## 1. JSON:API Format (Critical)

All requests MUST use JSON:API format:

```python
content_type = "application/vnd.api+json"

payload = {
    "data": {
        "type": "providers",  # Plural, kebab-case
        "id": str(resource.id),  # Required for PATCH
        "attributes": {"alias": "updated"},
        "relationships": {
            "provider_groups": {
                "data": [{"type": "provider-groups", "id": str(group.id)}]
            }
        }
    }
}

# Response access
response.json()["data"]["attributes"]["alias"]
response.json()["data"]["id"]
```

---

## 2. RLS Isolation Tests (Critical)

```python
@pytest.mark.django_db
class TestRLSIsolation:
    """Verify tenant data isolation."""

    def test_list_excludes_other_tenant(
        self, authenticated_client, providers_fixture, other_tenant_provider
    ):
        response = authenticated_client.get(reverse("provider-list"))
        ids = [p["id"] for p in response.json()["data"]]

        assert str(providers_fixture[0].id) in ids
        assert str(other_tenant_provider.id) not in ids

    def test_detail_returns_404_for_other_tenant(
        self, authenticated_client, other_tenant_provider
    ):
        response = authenticated_client.get(
            reverse("provider-detail", args=[other_tenant_provider.id])
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
```

---

## 3. RBAC Tests

### Visibility Tests

```python
@pytest.mark.django_db
class TestRBACVisibility:
    """Test unlimited_visibility vs limited visibility."""

    def test_unlimited_visibility_sees_all(
        self, authenticated_client_admin, providers_fixture
    ):
        """Admin with unlimited_visibility sees all providers."""
        response = authenticated_client_admin.get(reverse("provider-list"))
        assert len(response.json()["data"]) == len(providers_fixture)

    def test_limited_visibility_sees_only_assigned(
        self, authenticated_client_limited, provider_group_fixture
    ):
        """User sees only providers in their role's provider_groups."""
        response = authenticated_client_limited.get(reverse("provider-list"))

        returned_ids = {p["id"] for p in response.json()["data"]}
        expected_ids = {str(p.id) for p in provider_group_fixture.providers.all()}
        assert returned_ids == expected_ids
```

### Permission Tests

```python
@pytest.mark.django_db
class TestRBACPermissions:
    """Test permission flags on ViewSets."""

    def test_manage_providers_required_for_create(
        self, authenticated_client_readonly
    ):
        """User without manage_providers cannot create."""
        payload = {
            "data": {
                "type": "providers",
                "attributes": {"provider": "aws", "uid": "123456789012"},
            }
        }
        response = authenticated_client_readonly.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_readonly_can_list(self, authenticated_client_readonly, providers_fixture):
        """User without permissions can still read."""
        response = authenticated_client_readonly.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK
```

---

## 4. RBAC Fixtures

```python
@pytest.fixture
def authenticated_client_admin(create_test_user, tenants_fixture, client):
    """Client with unlimited_visibility and all permissions."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="admin",
            unlimited_visibility=True,
            manage_providers=True,
            manage_scans=True,
        )
        UserRoleRelationship.objects.create(
            user=user, role=role, tenant_id=tenant.id
        )

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def authenticated_client_limited(
    create_test_user, tenants_fixture, provider_group_fixture, client
):
    """Client with limited visibility to specific provider_group."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="limited",
            unlimited_visibility=False,  # Limited visibility
            manage_scans=True,
        )
        # Link role to provider_group for visibility
        RoleProviderGroupRelationship.objects.create(
            role=role,
            provider_group=provider_group_fixture,
            tenant_id=tenant.id,
        )
        UserRoleRelationship.objects.create(
            user=user, role=role, tenant_id=tenant.id
        )

    return _get_authenticated_client(client, user, tenant)


@pytest.fixture
def authenticated_client_readonly(create_test_user, tenants_fixture, client):
    """Client with no write permissions."""
    user = create_test_user
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            tenant_id=tenant.id,
            name="readonly",
            unlimited_visibility=True,
            manage_providers=False,
            manage_scans=False,
        )
        UserRoleRelationship.objects.create(
            user=user, role=role, tenant_id=tenant.id
        )

    return _get_authenticated_client(client, user, tenant)
```

---

## 5. ViewSet CRUD Tests

```python
@pytest.mark.django_db
class TestProviderViewSet:
    def test_create_validates_uid_format(self, authenticated_client):
        """Each provider type has specific UID validation."""
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": "aws",
                    "uid": "invalid",  # AWS requires 12 digits
                },
            }
        }
        response = authenticated_client.post(
            reverse("provider-list"),
            data=payload,
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_delete_is_soft_delete(self, authenticated_client, providers_fixture):
        """DELETE sets is_deleted=True, not hard delete."""
        provider = providers_fixture[0]
        response = authenticated_client.delete(
            reverse("provider-detail", args=[provider.id])
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        provider.refresh_from_db()
        assert provider.is_deleted is True
```

---

## 6. Manager Tests (objects vs all_objects)

```python
@pytest.mark.django_db
class TestProviderManagers:
    def test_objects_excludes_deleted(self, tenants_fixture):
        """Default manager filters is_deleted=False."""
        tenant = tenants_fixture[0]

        with rls_transaction(str(tenant.id)):
            active = Provider.objects.create(
                tenant_id=tenant.id, provider="aws",
                uid="111111111111", is_deleted=False,
            )
            deleted = Provider.objects.create(
                tenant_id=tenant.id, provider="aws",
                uid="222222222222", is_deleted=True,
            )

            assert active in Provider.objects.all()
            assert deleted not in Provider.objects.all()
            assert deleted in Provider.all_objects.all()

    def test_finding_objects_filters_by_active_provider(
        self, tenants_fixture, providers_fixture, scans_fixture
    ):
        """Finding.objects excludes findings from deleted providers."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        scan = scans_fixture[0]

        with rls_transaction(str(tenant.id)):
            finding = Finding.objects.create(
                tenant_id=tenant.id, scan=scan,
                check_id="test", status="FAIL", severity="high",
            )
            assert finding in Finding.objects.all()

            # Delete provider
            provider.is_deleted = True
            provider.save()

            # Finding hidden from objects, visible in all_objects
            assert finding not in Finding.objects.all()
            assert finding in Finding.all_objects.all()
```

---

## 7. Celery Task Tests

```python
@pytest.mark.django_db
class TestScanTask:
    @patch("tasks.tasks.perform_prowler_scan")
    def test_task_success(self, mock_scan):
        mock_scan.return_value = {"findings_count": 100}

        from tasks.tasks import perform_scan_task
        result = perform_scan_task(
            tenant_id="tenant-id",
            scan_id="scan-id",
            provider_id="provider-id",
        )

        assert result["findings_count"] == 100
        mock_scan.assert_called_once()

    @patch("tasks.tasks.perform_prowler_scan")
    def test_handles_provider_deletion(
        self, mock_scan, tenants_fixture, providers_fixture
    ):
        """@handle_provider_deletion catches ObjectDoesNotExist."""
        provider = providers_fixture[0]
        tenant = tenants_fixture[0]

        mock_scan.side_effect = ObjectDoesNotExist("Provider not found")
        provider.is_deleted = True
        provider.save()

        from tasks.tasks import perform_scan_task
        with pytest.raises(ProviderDeletedException):
            perform_scan_task(
                tenant_id=str(tenant.id),
                scan_id=str(uuid.uuid4()),
                provider_id=str(provider.id),
            )
```

---

## 8. Core Fixtures (conftest.py)

```python
# api/src/backend/conftest.py

TEST_USER = "dev@prowler.com"
TEST_PASSWORD = "testing_psswd"


@pytest.fixture(scope="session", autouse=True)
def create_test_user(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        user = User.objects.create_user(
            name="testing", email=TEST_USER, password=TEST_PASSWORD,
        )
    return user


@pytest.fixture
def tenants_fixture(create_test_user):
    """Create tenants for multi-tenant testing."""
    user = create_test_user

    tenant1 = Tenant.objects.create(name="Tenant One")
    Membership.objects.create(user=user, tenant=tenant1)

    tenant2 = Tenant.objects.create(name="Tenant Two")
    Membership.objects.create(user=user, tenant=tenant2)

    # Isolated tenant (user NOT member)
    tenant3 = Tenant.objects.create(name="Isolated")

    return tenant1, tenant2, tenant3


@pytest.fixture
def providers_fixture(tenants_fixture):
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        aws1 = Provider.objects.create(
            tenant_id=tenant.id, provider="aws",
            uid="111111111111", alias="aws-1",
        )
        gcp = Provider.objects.create(
            tenant_id=tenant.id, provider="gcp",
            uid="my-gcp-project", alias="gcp-1",
        )

    return aws1, gcp


@pytest.fixture
def other_tenant_provider(tenants_fixture):
    """Provider in isolated tenant for RLS tests."""
    tenant = tenants_fixture[2]

    with rls_transaction(str(tenant.id)):
        provider = Provider.objects.create(
            tenant_id=tenant.id, provider="aws",
            uid="999999999999", alias="other",
        )
    return provider


@pytest.fixture
def provider_group_fixture(tenants_fixture, providers_fixture):
    """Provider group with providers for RBAC tests."""
    tenant = tenants_fixture[0]

    with rls_transaction(str(tenant.id)):
        group = ProviderGroup.objects.create(
            tenant_id=tenant.id, name="Test Group",
        )
        for provider in providers_fixture[:1]:  # Only first provider
            ProviderGroupMembership.objects.create(
                tenant_id=tenant.id,
                provider_group=group,
                provider=provider,
            )
    return group


def _get_authenticated_client(client, user, tenant):
    """Helper to get JWT-authenticated client."""
    serializer = TokenSerializer(
        data={
            "type": "tokens",
            "email": user.email,
            "password": TEST_PASSWORD,
            "tenant_id": str(tenant.id),
        }
    )
    serializer.is_valid()
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {serializer.validated_data['access']}"
    client.tenant = tenant
    client.user = user
    return client
```

---

## Commands

```bash
cd api && poetry run pytest -x --tb=short        # Run all, stop on first failure
cd api && poetry run pytest -k "test_provider"   # Run by name
cd api && poetry run pytest -k "TestRBAC"        # Run by class
cd api && poetry run pytest --cov=api            # With coverage
```

---

## Resources

- **Templates**: See [assets/](assets/) for conftest.py, ViewSet tests, and Celery task test templates
- **API Patterns**: See `prowler-api` skill

## Keywords

prowler api test, pytest, django, rls, rbac, json:api, celery
