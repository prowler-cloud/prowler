# Prowler API File Locations

## RLS (Row-Level Security)

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **RLS Base Model** | `api/src/backend/api/rls.py` | `RowLevelSecurityProtectedModel`, `RowLevelSecurityConstraint` |
| **RLS Transaction** | `api/src/backend/api/db_utils.py` | `rls_transaction()` context manager |
| **RLS Serializer** | `api/src/backend/api/v1/serializers.py` | `RLSSerializer` - auto-injects tenant_id |
| **Tenant Model** | `api/src/backend/api/rls.py` | `Tenant` model |

## RBAC (Role-Based Access Control)

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Permissions** | `api/src/backend/api/rbac/permissions.py` | `Permissions` enum, `get_role()`, `get_providers()` |
| **Role Model** | `api/src/backend/api/models.py` | `Role`, `UserRoleRelationship` |
| **Permission Decorator** | `api/src/backend/api/decorators.py` | `@check_permissions`, `HasPermissions` |

## Providers

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Provider Model** | `api/src/backend/api/models.py` | `Provider`, `ProviderChoices` |
| **UID Validation** | `api/src/backend/api/models.py` | `validate_<provider>_uid()` staticmethods |
| **Provider Secret** | `api/src/backend/api/models.py` | `ProviderSecret` model |
| **Provider Groups** | `api/src/backend/api/models.py` | `ProviderGroup`, `ProviderGroupMembership` |

## Celery Tasks

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Task Definitions** | `api/src/backend/tasks/tasks.py` | All `@shared_task` definitions |
| **RLS Task Base** | `api/src/backend/tasks/__init__.py` | `RLSTask` base class |
| **Task Decorators** | `api/src/backend/tasks/utils.py` | `@set_tenant`, `@handle_provider_deletion` |
| **Celery Config** | `api/src/backend/config/celery.py` | Celery app configuration |
| **Beat Schedule** | `api/src/backend/tasks/beat.py` | Periodic task scheduling |

## Key Line References

### RLS Transaction (api/src/backend/api/db_utils.py)
```python
# Usage pattern
from api.db_utils import rls_transaction

with rls_transaction(tenant_id):
    # All queries here are tenant-scoped
    providers = Provider.objects.filter(connected=True)
```

### RBAC Check (api/src/backend/api/rbac/permissions.py)
```python
# Usage pattern
from api.rbac.permissions import get_role, get_providers, Permissions

user_role = get_role(request.user)  # Returns FIRST role only
if user_role.unlimited_visibility:
    queryset = Provider.objects.all()
else:
    queryset = get_providers(user_role)
```

### Celery Task (api/src/backend/tasks/tasks.py)
```python
# Usage pattern
@shared_task(base=RLSTask, name="task-name", queue="scans")
@set_tenant
@handle_provider_deletion
def my_task(tenant_id: str, provider_id: str):
    with rls_transaction(tenant_id):
        provider = Provider.objects.get(pk=provider_id)
```

## Related Skills

- **Generic DRF patterns**: Use `django-drf` skill for ViewSets, Serializers, Filters, JSON:API
- **API Testing**: Use `prowler-test-api` skill for testing patterns
