---
name: prowler-test-api
description: >
  Testing patterns for Prowler API: JSON:API, Celery tasks, RLS isolation, RBAC.
  Trigger: When writing tests for api/ (JSON:API requests/assertions, cross-tenant isolation, RBAC, Celery tasks, viewsets/serializers).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
  scope: [root, api]
  auto_invoke:
    - "Writing Prowler API tests"
    - "Testing RLS tenant isolation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- ALWAYS use `response.json()["data"]` not `response.data`
- ALWAYS send JSON:API bodies (`{"data": {...}}`) with `content_type=API_JSON_CONTENT_TYPE` (from `conftest`) for POST/PATCH/PUT
- `authenticated_client` is Django's test `Client`, NOT DRF's `APIClient`: `format=` is silently ignored and the body is sent multipart. Existing tests that pass `format="json"` only work because they post flat dicts
- ALWAYS mark DB tests with `@pytest.mark.django_db`
- ALWAYS test cross-tenant isolation - RLS returns 404, NOT 403
- NEVER skip RLS isolation tests when adding new endpoints
- NEVER use realistic-looking API keys in tests (TruffleHog will flag them)
- ALWAYS mock BOTH `.delay()` AND `Task.objects.get` for views that return 202 with a task
- ALWAYS patch the job function where `tasks.tasks` imports it (e.g. `tasks.tasks.check_provider_connection`) when calling `task.apply()`; never reach real cloud APIs
- Valid provider UIDs only: `Provider.save()` runs `full_clean()` and the `validate_<provider>_uid()` checks

---

## 1. Fixture Dependency Chain

```text
create_test_user (session) ─► tenants_fixture (function) ─► authenticated_client
                                     │
                                     └─► aws_provider ─► scans_fixture ─► findings_fixture
```

### Key Fixtures

| Fixture | Description |
|---------|-------------|
| `create_test_user` | Session user (`dev@prowler.com`) |
| `tenants_fixture` | 3 tenants: [0],[1] have membership ([1] as OWNER), [2] isolated |
| `authenticated_client` | Django test client with JWT for tenant[0] |
| `authenticated_client_for_tenant_factory` | Creates a Django test client with JWT for a specific user and tenant |
| `provider_factory` | Creates one validated provider with provider-specific defaults |
| `aws_provider` | 1 AWS provider in tenant[0] |
| `aws_provider_pair` | 2 AWS providers in tenant[0] |
| `all_provider_types_fixture` | 1 provider for every supported provider type |
| `tasks_fixture` | 2 `Task` rows in tenant[0] backed by `TaskResult` |
| `authenticated_api_client` | DRF `APIClient` with a serializer-issued JWT (use only for token tests) |

### RBAC Fixtures

| Fixture | Permissions |
|---------|-------------|
| `authenticated_client_rbac` | All permissions (admin) |
| `authenticated_client_rbac_noroles` | Membership but NO roles |
| `authenticated_client_no_permissions_rbac` | All permissions = False |

Use `authenticated_client` for normal view behavior tests. It uses a cheap JWT
and still runs the real request authentication path. Use serializer-generated
JWTs or API-key clients only when the test is specifically about token
obtain/refresh, invalid tokens, expired tokens, tenant switching by token, API
keys, or unauthenticated 401 behavior. Use
`authenticated_client_for_tenant_factory` when a test needs a cheap JWT client
for a different user or tenant.

---

## 2. JSON:API Requests

```python
from conftest import API_JSON_CONTENT_TYPE  # "application/vnd.api+json"
```

### POST (Create)
```python
response = authenticated_client.post(
    reverse("scan-list"),
    data={"data": {"type": "scans", "attributes": {...}, "relationships": {...}}},
    content_type=API_JSON_CONTENT_TYPE,
)
```

### PATCH (Update)
```python
response = authenticated_client.patch(
    reverse("provider-detail", kwargs={"pk": provider.id}),
    data={"data": {"type": "providers", "id": str(provider.id), "attributes": {...}}},
    content_type=API_JSON_CONTENT_TYPE,
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
| Mock `api.v1.views.enqueue_scan_execution_on_commit` | Testing scan creation (`POST /scans`) |
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
| Async operation (provider DELETE, `POST /scans`, connection checks) | 202 |
| Sync DELETE | 204 |
| Validation error | 400 |
| Missing/invalid token or no tenant in token | 401 |
| Missing permission (RBAC) | 403 |
| RLS isolation / not found | 404 |

---

## Commands

```bash
# pytest.ini is in api/src/backend; needs PostgreSQL + Valkey and a shell WITHOUT the dev .env
cd api/src/backend && uv run pytest -x --tb=short
cd api/src/backend && uv run pytest -k "test_provider"
cd api/src/backend && uv run pytest api/tests/test_rbac.py
cd api/src/backend && uv run pytest tasks/tests/test_tasks.py
```

Test order is randomized (`pytest-randomly`): never rely on state from another test.

---

## Resources

- **Full Examples**: See [assets/api_test.py](assets/api_test.py) for complete test patterns
- **Fixture Reference**: See [references/test-api-docs.md](references/test-api-docs.md)
- **Fixture Source**: `api/src/backend/conftest.py`
