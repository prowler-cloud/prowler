# API Test Documentation Reference

## File Locations

| Type | Path |
|------|------|
| Central fixtures | `api/src/backend/conftest.py` |
| API unit tests | `api/src/backend/api/tests/` |
| Integration tests | `api/src/backend/api/tests/integration/` |
| Task tests | `api/src/backend/tasks/tests/` |
| Dev fixtures (JSON) | `api/src/backend/api/fixtures/dev/` |

---

## Fixture Dependency Graph

```
create_test_user (session)
    │
    └─► tenants_fixture (function)
            │
            ├─► set_user_admin_roles_fixture
            │       │
            │       └─► authenticated_client
            │               └─► (most API tests use this)
            │
            ├─► providers_fixture
            │       └─► scans_fixture
            │               └─► findings_fixture
            │
            └─► RBAC fixtures (create their own tenants/users):
                    ├─► create_test_user_rbac
                    │       └─► authenticated_client_rbac
                    │
                    ├─► create_test_user_rbac_no_roles
                    │       └─► authenticated_client_rbac_noroles
                    │
                    ├─► create_test_user_rbac_limited
                    │       └─► authenticated_client_no_permissions_rbac
                    │
                    ├─► create_test_user_rbac_manage_account
                    │       └─► authenticated_client_rbac_manage_account
                    │
                    └─► create_test_user_rbac_manage_users_only
                            └─► authenticated_client_rbac_manage_users_only
```

---

## Test File Contents

### `api/src/backend/api/tests/test_views.py`

Main ViewSet tests covering:
- `TestUserViewSet` - User CRUD, password validation, deletion cascades
- `TestTenantViewSet` - Tenant operations
- `TestProviderViewSet` - Provider CRUD, async deletion, connection testing
- `TestScanViewSet` - Scan trigger, list, filter
- `TestFindingViewSet` - Finding queries, filters
- `TestResourceViewSet` - Resource listing with tags
- `TestTaskViewSet` - Celery task status
- `TestIntegrationViewSet` - S3/Security Hub integrations
- `TestComplianceOverviewViewSet` - Compliance data
- And many more...

### `api/src/backend/api/tests/test_rbac.py`

RBAC permission tests covering:
- Permission checks for each ViewSet
- Role-based access patterns
- `unlimited_visibility` behavior
- Provider group visibility filtering
- Self-access patterns (`/me` endpoint)

### `api/src/backend/api/tests/integration/test_rls_transaction.py`

RLS enforcement tests:
- `rls_transaction` context manager
- Invalid UUID validation
- Custom parameter names

### `api/src/backend/api/tests/integration/test_providers.py`

Provider integration tests:
- Delete + recreate flow with async tasks
- End-to-end provider lifecycle

### `api/src/backend/api/tests/integration/test_authentication.py`

Authentication tests:
- JWT token flow
- API key authentication
- Social login (SAML, OAuth)
- Cross-tenant token isolation

---

## Key Test Classes and Their Fixtures

### Standard API Tests

```python
@pytest.mark.django_db
class TestProviderViewSet:
    def test_list(self, authenticated_client, providers_fixture):
        # authenticated_client has JWT for tenant[0]
        # providers_fixture has 9 providers in tenant[0]
        ...
```

### RBAC Tests

```python
@pytest.mark.django_db
class TestProviderRBAC:
    def test_with_permission(self, authenticated_client_rbac, ...):
        # Has all permissions
        ...

    def test_without_permission(self, authenticated_client_no_permissions_rbac, ...):
        # Has no permissions (all False)
        ...
```

### Cross-Tenant Tests

```python
@pytest.mark.django_db
class TestCrossTenantIsolation:
    def test_cannot_access_other_tenant(self, authenticated_client, tenants_fixture):
        other_tenant = tenants_fixture[2]  # Isolated tenant
        # Create resource in other_tenant
        # Try to access with authenticated_client
        # Expect 404
```

### Async Task Tests

```python
@pytest.mark.django_db
class TestAsyncOperations:
    @patch("api.v1.views.Task.objects.get")
    @patch("api.v1.views.some_task.delay")
    def test_async_operation(self, mock_task, mock_task_get, tasks_fixture, ...):
        prowler_task = tasks_fixture[0]
        mock_task.return_value = Mock(id=prowler_task.id)
        mock_task_get.return_value = prowler_task
        # Execute and verify 202 response
```

---

## Constants Available from conftest

```python
from conftest import (
    API_JSON_CONTENT_TYPE,  # "application/vnd.api+json"
    NO_TENANT_HTTP_STATUS,  # status.HTTP_401_UNAUTHORIZED
    TEST_USER,              # "dev@prowler.com"
    TEST_PASSWORD,          # "testing_psswd"
    TODAY,                  # str(datetime.today().date())
    today_after_n_days,     # Function: (n: int) -> str
    get_api_tokens,         # Function: (client, email, password, tenant_id?) -> (access, refresh)
    get_authorization_header,  # Function: (token) -> {"Authorization": f"Bearer {token}"}
)
```

---

## Running Tests

```bash
# Full test suite
cd api && poetry run pytest

# Fast fail on first error
cd api && poetry run pytest -x

# Short traceback
cd api && poetry run pytest --tb=short

# Specific file
cd api && poetry run pytest api/src/backend/api/tests/test_views.py

# Pattern match
cd api && poetry run pytest -k "Provider"

# Verbose with print output
cd api && poetry run pytest -v -s

# With coverage
cd api && poetry run pytest --cov=api --cov-report=html

# Parallel execution
cd api && poetry run pytest -n auto
```

---

## pytest Configuration

From `api/pyproject.toml`:

```toml
[tool.pytest.ini_options]
DJANGO_SETTINGS_MODULE = "config.settings"
python_files = "test_*.py"
addopts = "--reuse-db"
```

Key points:
- Uses `--reuse-db` for faster test runs
- Settings from `config.settings`
- Test files must match `test_*.py`
