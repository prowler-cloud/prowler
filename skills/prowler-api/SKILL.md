---
name: prowler-api
description: >
  Prowler API patterns: JSON:API, RLS, RBAC, providers, Celery tasks.
  Trigger: When working in api/ on models/serializers/viewsets/filters/tasks involving tenant isolation (RLS), RBAC, JSON:API, or provider lifecycle.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, api]
  auto_invoke: "Creating/modifying models, views, serializers"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Rules

- ALWAYS use `rls_transaction(tenant_id)` when querying outside ViewSet context
- ALWAYS use `get_role()` before checking permissions (returns FIRST role only)
- NEVER access `Provider.objects` without RLS context in Celery tasks
- ALWAYS use `@set_tenant` then `@handle_provider_deletion` decorator order

---

## 1. Providers (10 Supported)

UID validation is dynamic: `getattr(self, f"validate_{self.provider}_uid")(self.uid)`

| Provider | UID Format | Example |
|----------|-----------|---------|
| AWS | 12 digits | `123456789012` |
| Azure | UUID v4 | `a1b2c3d4-e5f6-...` |
| GCP | 6-30 chars, lowercase, letter start | `my-gcp-project` |
| M365 | Valid domain | `contoso.onmicrosoft.com` |
| Kubernetes | 2-251 chars | `arn:aws:eks:...` |
| GitHub | 1-39 chars | `my-org` |
| IaC | Git URL | `https://github.com/user/repo.git` |
| Oracle Cloud | OCID format | `ocid1.tenancy.oc1..` |
| MongoDB Atlas | 24-char hex | `507f1f77bcf86cd799439011` |
| Alibaba Cloud | 16 digits | `1234567890123456` |

**Adding new provider**: Add to `ProviderChoices` enum + create `validate_<provider>_uid()` staticmethod.

---

## 2. Row-Level Security (RLS)

```python
from api.db_utils import rls_transaction

with rls_transaction(tenant_id):
    providers = Provider.objects.filter(connected=True)
    # PostgreSQL enforces tenant_id automatically
```

Models inherit from `RowLevelSecurityProtectedModel` with `RowLevelSecurityConstraint`.

---

## 3. Managers

```python
Provider.objects.all()       # Only is_deleted=False
Provider.all_objects.all()   # All including deleted
Finding.objects.all()        # Only from active providers
```

---

## 4. RBAC

```python
from api.rbac.permissions import get_role, get_providers, Permissions

user_role = get_role(self.request.user)  # Returns FIRST role only

if user_role.unlimited_visibility:
    queryset = Provider.objects.filter(tenant_id=tenant_id)
else:
    queryset = get_providers(user_role)  # Filtered by provider_groups
```

**Permissions**: `MANAGE_USERS`, `MANAGE_ACCOUNT`, `MANAGE_BILLING`, `MANAGE_PROVIDERS`, `MANAGE_INTEGRATIONS`, `MANAGE_SCANS`, `UNLIMITED_VISIBILITY`

---

## 5. Celery Tasks

```python
@shared_task(base=RLSTask, name="task-name", queue="scans")
@set_tenant
@handle_provider_deletion
def my_task(tenant_id: str, provider_id: str):
    pass
```

**Queues**: Check `tasks/tasks.py`. Common: `scans`, `overview`, `compliance`, `integrations`.

**Orchestration**: Use `chain()` for sequential, `group()` for parallel.

---

## 6. JSON:API Format

```python
content_type = "application/vnd.api+json"

# Request
{"data": {"type": "providers", "attributes": {"provider": "aws", "uid": "123456789012"}}}

# Response access
response.json()["data"]["attributes"]["alias"]
```

---

## 7. Serializers

| Pattern | Usage |
|---------|-------|
| `ProviderSerializer` | Read (list/retrieve) |
| `ProviderCreateSerializer` | POST |
| `ProviderUpdateSerializer` | PATCH |
| `RLSSerializer` | Auto-injects tenant_id |

---

## Commands

```bash
cd api && poetry run python manage.py migrate      # Run migrations
cd api && poetry run python manage.py shell        # Django shell
cd api && poetry run celery -A config.celery worker -l info  # Start worker
```

---

## Resources

- **Documentation**: See [references/api-docs.md](references/api-docs.md) for local file paths and documentation
