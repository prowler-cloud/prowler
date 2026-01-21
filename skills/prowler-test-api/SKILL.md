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

### 4.1 Testing Views That Trigger Tasks

**Mock BOTH `.delay()` AND `Task.objects.get`**:

```python
@patch("api.v1.views.Task.objects.get")
@patch("api.v1.views.delete_provider_task.delay")
def test_async_delete(self, mock_task, mock_task_get, authenticated_client, providers_fixture, tasks_fixture):
    provider = providers_fixture[0]
    prowler_task = tasks_fixture[0]
    mock_task.return_value = Mock(id=prowler_task.id)
    mock_task_get.return_value = prowler_task

    response = authenticated_client.delete(reverse("provider-detail", kwargs={"pk": provider.id}))
    assert response.status_code == status.HTTP_202_ACCEPTED
    mock_task.assert_called_once()
```

### 4.2 Testing Task Logic Directly

Use `apply()` for synchronous execution without Celery worker:

```python
@pytest.mark.django_db
def test_task_logic_directly(self, tenants_fixture, providers_fixture):
    tenant = tenants_fixture[0]
    provider = providers_fixture[0]

    # Execute task synchronously (no broker needed)
    result = check_provider_connection_task.apply(
        kwargs={"tenant_id": str(tenant.id), "provider_id": str(provider.id)}
    )

    assert result.successful()
    assert result.result["connected"] is True
```

### 4.3 Testing Canvas (chain/group)

Mock the entire chain to verify task orchestration:

```python
@patch("tasks.tasks.chain")
@patch("tasks.tasks.group")
def test_post_scan_workflow(self, mock_group, mock_chain, tenants_fixture):
    tenant = tenants_fixture[0]

    # Mock chain.apply_async
    mock_chain_instance = Mock()
    mock_chain.return_value = mock_chain_instance

    _perform_scan_complete_tasks(str(tenant.id), "scan-123", "provider-456")

    # Verify chain was called
    assert mock_chain.called
    mock_chain_instance.apply_async.assert_called()
```

### 4.4 Why NOT to Use `task_always_eager`

> **Warning:** `CELERY_TASK_ALWAYS_EAGER = True` is NOT recommended for testing.

| Problem | Impact |
|---------|--------|
| No actual task serialization | Misses argument type errors |
| No broker interaction | Hides connection issues |
| Different execution context | `self.request` behaves differently |
| Results not stored by default | `task.result` returns `None` |

**Instead, use:**
- `task.apply()` for synchronous execution
- Mocking for isolation
- `pytest-celery` for integration tests

### 4.5 Testing Tasks with `@set_tenant`

The `@set_tenant` decorator pops `tenant_id` from kwargs (unless `keep_tenant=True`).

```python
from unittest.mock import patch, Mock
from tasks.tasks import check_provider_connection_task

@pytest.mark.django_db
class TestSetTenantDecorator:
    @patch("api.decorators.connection")
    def test_sets_rls_context(self, mock_conn, tenants_fixture, providers_fixture):
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]

        # Call task with tenant_id - decorator sets RLS and pops it
        check_provider_connection_task.apply(
            kwargs={"tenant_id": str(tenant.id), "provider_id": str(provider.id)}
        )

        # Verify SET_CONFIG_QUERY was executed
        mock_conn.cursor.return_value.__enter__.return_value.execute.assert_called()
```

### 4.6 Testing Beat Scheduled Tasks

```python
from unittest.mock import patch, Mock
from django_celery_beat.models import PeriodicTask
from tasks.beat import schedule_provider_scan

@pytest.mark.django_db
class TestBeatScheduling:
    @patch("tasks.beat.perform_scheduled_scan_task.apply_async")
    def test_schedule_provider_scan(self, mock_apply, providers_fixture):
        provider = providers_fixture[0]
        mock_apply.return_value = Mock(id="task-123")

        schedule_provider_scan(provider)

        # Verify periodic task created
        assert PeriodicTask.objects.filter(
            name=f"scan-perform-scheduled-{provider.id}"
        ).exists()

        # Verify immediate execution with countdown
        mock_apply.assert_called_once()
        call_kwargs = mock_apply.call_args
        assert call_kwargs.kwargs.get("countdown") == 5
```

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
