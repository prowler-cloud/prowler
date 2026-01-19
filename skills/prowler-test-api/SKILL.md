---
name: prowler-test-api
description: >
  Testing patterns for Prowler API: JSON:API, Celery tasks, RLS isolation, RBAC.
  Trigger: When writing tests for api/ (JSON:API requests/assertions, cross-tenant isolation, RBAC, Celery tasks, viewsets/serializers).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, api]
  auto_invoke:
    - "Writing Prowler API tests"
    - "Testing RLS tenant isolation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- ALWAYS use `response.json()["data"]` not `response.data`
- ALWAYS use `content_type = "application/vnd.api+json"` in requests
- ALWAYS test cross-tenant isolation with `other_tenant_provider` fixture
- NEVER skip RLS isolation tests when adding new endpoints
- NEVER use realistic-looking API keys in tests (TruffleHog will flag them)

---

## 1. JSON:API Format (Critical)

```python
content_type = "application/vnd.api+json"

payload = {
    "data": {
        "type": "providers",  # Plural, kebab-case
        "id": str(resource.id),  # Required for PATCH
        "attributes": {"alias": "updated"},
    }
}

response.json()["data"]["attributes"]["alias"]
```

---

## 2. RLS Isolation Tests

```python
def test_cross_tenant_access_denied(self, authenticated_client, other_tenant_provider):
    """User cannot see resources from other tenants."""
    response = authenticated_client.get(
        reverse("provider-detail", args=[other_tenant_provider.id])
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
```

---

## 3. RBAC Tests

```python
def test_unlimited_visibility_sees_all(self, authenticated_client_admin, providers_fixture):
    response = authenticated_client_admin.get(reverse("provider-list"))
    assert len(response.json()["data"]) == len(providers_fixture)

def test_limited_visibility_sees_only_assigned(self, authenticated_client_limited):
    # User with unlimited_visibility=False sees only providers in their provider_groups
    pass

def test_permission_required(self, authenticated_client_readonly):
    response = authenticated_client_readonly.post(reverse("provider-list"), ...)
    assert response.status_code == status.HTTP_403_FORBIDDEN
```

---

## 4. Managers (objects vs all_objects)

```python
def test_objects_excludes_deleted(self):
    deleted_provider = Provider.objects.create(..., is_deleted=True)
    assert deleted_provider not in Provider.objects.all()
    assert deleted_provider in Provider.all_objects.all()
```

---

## 5. Celery Task Tests

```python
@patch("tasks.tasks.perform_prowler_scan")
def test_task_success(self, mock_scan):
    mock_scan.return_value = {"findings_count": 100}
    result = perform_scan_task(tenant_id="...", scan_id="...", provider_id="...")
    assert result["findings_count"] == 100
```

---

## 6. Key Fixtures

| Fixture | Description |
|---------|-------------|
| `create_test_user` | Session user (dev@prowler.com) |
| `tenants_fixture` | 3 tenants (2 with membership, 1 isolated) |
| `providers_fixture` | Providers in tenant 1 |
| `other_tenant_provider` | Provider in isolated tenant (RLS tests) |
| `authenticated_client` | Client with JWT for tenant 1 |

---

## 7. Fake Secrets in Tests (TruffleHog)

CI runs TruffleHog to detect leaked secrets. Use obviously fake values:

```python
# BAD - TruffleHog will flag these patterns:
api_key = "sk-test1234567890T3BlbkFJtest1234567890"  # OpenAI pattern
api_key = "AKIA..."  # AWS pattern

# GOOD - clearly fake values:
api_key = "sk-fake-test-key-for-unit-testing-only"
api_key = "fake-aws-key-for-testing"
```

**Patterns to avoid:**
- `sk-*T3BlbkFJ*` (OpenAI)
- `AKIA[A-Z0-9]{16}` (AWS Access Key)
- `ghp_*` or `gho_*` (GitHub tokens)

---

## Commands

```bash
cd api && poetry run pytest -x --tb=short
cd api && poetry run pytest -k "test_provider"
cd api && poetry run pytest -k "TestRBAC"
```

---

## Resources

- **Documentation**: See [references/test-api-docs.md](references/test-api-docs.md) for local file paths and documentation
