---
name: prowler-test-api
description: >
  Testing patterns for Prowler API: JSON:API, Celery tasks, RLS isolation, RBAC.
  Trigger: When writing tests for api/ (JSON:API requests/assertions, cross-tenant isolation, RBAC, Celery tasks, viewsets/serializers).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1.0"
  scope: [root, api]
  auto_invoke:
    - "Writing Prowler API tests"
    - "Testing RLS tenant isolation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- ALWAYS use `response.json()["data"]` not `response.data`
- ALWAYS use `content_type = "application/vnd.api+json"` for PATCH/PUT requests
- ALWAYS use `format="vnd.api+json"` for POST requests
- ALWAYS test cross-tenant isolation - RLS returns 404, NOT 403
- NEVER skip RLS isolation tests when adding new endpoints
- NEVER use realistic-looking API keys in tests (TruffleHog will flag them)
- ALWAYS mock BOTH `.delay()` AND `Task.objects.get` for async task tests

---

## 1. Fixture Dependency Chain

```
create_test_user (session) ─► tenants_fixture (function) ─► authenticated_client
                                     │
                                     └─► providers_fixture ─► scans_fixture ─► findings_fixture
```

### Key Fixtures

| Fixture | Description |
|---------|-------------|
| `create_test_user` | Session user (`dev@prowler.com`) |
| `tenants_fixture` | 3 tenants: [0],[1] have membership, [2] isolated |
| `authenticated_client` | JWT client for tenant[0] |
| `providers_fixture` | 9 providers in tenant[0] |
| `tasks_fixture` | 2 Celery tasks with TaskResult |

### RBAC Fixtures

| Fixture | Permissions |
|---------|-------------|
| `authenticated_client_rbac` | All permissions (admin) |
| `authenticated_client_rbac_noroles` | Membership but NO roles |
| `authenticated_client_no_permissions_rbac` | All permissions = False |

---

## 2. JSON:API Requests

### POST (Create)
```python
response = client.post(
    reverse("provider-list"),
    data={"data": {"type": "providers", "attributes": {...}}},
    format="vnd.api+json",  # NOT content_type!
)
```

### PATCH (Update)
```python
response = client.patch(
    reverse("provider-detail", kwargs={"pk": provider.id}),
    data={"data": {"type": "providers", "id": str(provider.id), "attributes": {...}}},
    content_type="application/vnd.api+json",  # NOT format!
)
```

### Reading Responses
```python
data = response.json()["data"]
attrs = data["attributes"]
errors = response.json()["errors"]  # For 400 responses
```

---

## 3. RLS Isolation (Cross-Tenant)

**RLS returns 404, NOT 403** - the resource is invisible, not forbidden.

```python
def test_cross_tenant_access_denied(self, authenticated_client, tenants_fixture):
    other_tenant = tenants_fixture[2]  # Isolated tenant
    foreign_provider = Provider.objects.create(tenant_id=other_tenant.id, ...)

    response = authenticated_client.get(reverse("provider-detail", args=[foreign_provider.id]))
    assert response.status_code == status.HTTP_404_NOT_FOUND  # NOT 403!
```

---

## 4. Celery Task Testing

### Testing Strategies

| Strategy | Use For |
|----------|---------|
| Mock `.delay()` + `Task.objects.get` | Testing views that trigger tasks |
| `task.apply()` | Synchronous task logic testing |
| Mock `chain`/`group` | Testing Canvas orchestration |
| Mock `connection` | Testing `@set_tenant` decorator |
| Mock `apply_async` | Testing Beat scheduled tasks |

### Why NOT `task_always_eager`

| Problem | Impact |
|---------|--------|
| No task serialization | Misses argument type errors |
| No broker interaction | Hides connection issues |
| Different execution context | `self.request` behaves differently |

**Instead, use:** `task.apply()` for sync execution, mocking for isolation.

> **Full examples:** See [assets/api_test.py](assets/api_test.py) for `TestCeleryTaskLogic`, `TestCeleryCanvas`, `TestSetTenantDecorator`, `TestBeatScheduling`.

---

## 5. Fake Secrets (TruffleHog)

```python
# BAD - TruffleHog flags these:
api_key = "sk-test1234567890T3BlbkFJtest1234567890"

# GOOD - obviously fake:
api_key = "sk-fake-test-key-for-unit-testing-only"
```

---

## 6. Response Status Codes

| Scenario | Code |
|----------|------|
| Successful GET | 200 |
| Successful POST | 201 |
| Async operation (DELETE/scan trigger) | 202 |
| Sync DELETE | 204 |
| Validation error | 400 |
| Missing permission (RBAC) | 403 |
| RLS isolation / not found | 404 |

---

## Commands

```bash
cd api && poetry run pytest -x --tb=short
cd api && poetry run pytest -k "test_provider"
cd api && poetry run pytest api/src/backend/api/tests/test_rbac.py
```

---

## Resources

- **Full Examples**: See [assets/api_test.py](assets/api_test.py) for complete test patterns
- **Fixture Reference**: See [references/test-api-docs.md](references/test-api-docs.md)
- **Fixture Source**: `api/src/backend/conftest.py`
