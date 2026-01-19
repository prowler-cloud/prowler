---
name: prowler-api
description: >
  Prowler API patterns: RLS, RBAC, providers, Celery tasks.
  Trigger: When working in api/ on models/serializers/viewsets/filters/tasks involving tenant isolation (RLS), RBAC, or provider lifecycle.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, api]
  auto_invoke: "Creating/modifying models, views, serializers"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

Use this skill for **Prowler-specific** patterns:
- Row-Level Security (RLS) / tenant isolation
- RBAC permissions and role checks
- Provider lifecycle and validation
- Celery tasks with tenant context

For **generic DRF patterns** (ViewSets, Serializers, Filters, JSON:API), use `django-drf` skill.

---

## Critical Rules

- ALWAYS use `rls_transaction(tenant_id)` when querying outside ViewSet context
- ALWAYS use `get_role()` before checking permissions (returns FIRST role only)
- ALWAYS use `@set_tenant` then `@handle_provider_deletion` decorator order
- NEVER access `Provider.objects` without RLS context in Celery tasks
- NEVER bypass RLS by using raw SQL or `connection.cursor()`

---

## Implementation Checklist

When implementing Prowler-specific API features:

| # | Pattern | Reference | Key Points |
|---|---------|-----------|------------|
| 1 | **RLS Models** | `api/models.py` | Inherit `RowLevelSecurityProtectedModel`, add `tenant_id` |
| 2 | **RLS Transactions** | `api/db_utils.py` | Use `rls_transaction(tenant_id)` context manager |
| 3 | **RBAC Permissions** | `api/rbac/permissions.py` | `get_role()`, `get_providers()`, `Permissions` enum |
| 4 | **Provider Validation** | `api/models.py` | `validate_<provider>_uid()` methods on `Provider` model |
| 5 | **Celery Tasks** | `tasks/tasks.py` | `@set_tenant`, `@handle_provider_deletion`, `RLSTask` base |
| 6 | **RLS Serializers** | `api/v1/serializers.py` | Inherit `RLSSerializer` to auto-inject `tenant_id` |

> **Full file paths**: See [references/file-locations.md](references/file-locations.md)

---

## Decision Trees

### Which Base Model?
```
Tenant-scoped data       → RowLevelSecurityProtectedModel
Global/shared data       → models.Model (rare)
Soft-deletable           → Add is_deleted + custom manager
```

### Which Manager?
```
Normal queries           → Model.objects (excludes deleted)
Include deleted records  → Model.all_objects
Celery task context      → Must use rls_transaction() first
```

### Celery Task Decorator Order?
```
@shared_task(base=RLSTask, name="...", queue="...")
@set_tenant                    # First: sets tenant context
@handle_provider_deletion      # Second: handles deleted providers
def my_task(tenant_id, provider_id):
    pass
```

---

## Providers (10 Supported)

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

## RBAC Permissions

| Permission | Controls |
|------------|----------|
| `MANAGE_USERS` | User CRUD, role assignments |
| `MANAGE_ACCOUNT` | Tenant settings |
| `MANAGE_BILLING` | Billing/subscription |
| `MANAGE_PROVIDERS` | Provider CRUD |
| `MANAGE_INTEGRATIONS` | Integration config |
| `MANAGE_SCANS` | Scan execution |
| `UNLIMITED_VISIBILITY` | See all providers (bypasses provider_groups) |

---

## Celery Queues

| Queue | Purpose |
|-------|---------|
| `scans` | Prowler scan execution |
| `overview` | Dashboard aggregations |
| `compliance` | Compliance report generation |
| `integrations` | External integrations (Jira, etc.) |

---

## Commands

```bash
# Development
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run python src/backend/manage.py shell

# Celery
cd api && poetry run celery -A config.celery worker -l info -Q scans,overview
cd api && poetry run celery -A config.celery beat -l info

# Testing
cd api && poetry run pytest -x --tb=short
```

---

## Resources

- **File Locations**: See [references/file-locations.md](references/file-locations.md)
- **Generic DRF Patterns**: Use `django-drf` skill
- **API Testing**: Use `prowler-test-api` skill
