# Prowler API File Locations

## Configuration

| Purpose | File Path | Key Items |
|---------|-----------|-----------|
| **Django Settings** | `api/src/backend/config/settings.py` | REST_FRAMEWORK, SIMPLE_JWT, DATABASES |
| **Celery Config** | `api/src/backend/config/celery.py` | Celery app, queues, task routing |
| **URL Routing** | `api/src/backend/config/urls.py` | Main URL patterns |
| **Database Router** | `api/src/backend/api/db_router.py` | `MainRouter` (4-database architecture) |

## RLS (Row-Level Security)

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **RLS Base Model** | `api/src/backend/api/rls.py` | `RowLevelSecurityProtectedModel`, `RowLevelSecurityConstraint` |
| **RLS Transaction** | `api/src/backend/api/db_utils.py` | `rls_transaction()` context manager |
| **RLS Serializer** | `api/src/backend/api/v1/serializers.py` | `RLSSerializer` - auto-injects tenant_id |
| **Tenant Model** | `api/src/backend/api/rls.py` | `Tenant` model |
| **Partitioning** | `api/src/backend/api/partitions.py` | `PartitionManager`, UUIDv7 partitioning |

## RBAC (Role-Based Access Control)

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Permissions** | `api/src/backend/api/rbac/permissions.py` | `Permissions` enum, `get_role()`, `get_providers()` |
| **Role Model** | `api/src/backend/api/models.py` | `Role`, `UserRoleRelationship`, `RoleProviderGroupRelationship` |
| **Permission Decorator** | `api/src/backend/api/decorators.py` | `@check_permissions`, `HasPermissions` |
| **Visibility Filter** | `api/src/backend/api/rbac/` | Provider group visibility filtering |

## Providers

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Provider Model** | `api/src/backend/api/models.py` | `Provider`, `ProviderChoices` |
| **UID Validation** | `api/src/backend/api/models.py` | `validate_<provider>_uid()` staticmethods |
| **Provider Secret** | `api/src/backend/api/models.py` | `ProviderSecret` model |
| **Provider Groups** | `api/src/backend/api/models.py` | `ProviderGroup`, `ProviderGroupMembership` |

## Serializers

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Base Serializers** | `api/src/backend/api/v1/serializers.py` | `BaseModelSerializerV1`, `RLSSerializer`, `BaseWriteSerializer` |
| **ViewSet Helpers** | `api/src/backend/api/v1/serializers.py` | `get_serializer_class_for_view()` |

## ViewSets

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Base ViewSets** | `api/src/backend/api/v1/views.py` | `BaseViewSet`, `BaseRLSViewSet`, `BaseTenantViewset`, `BaseUserViewset` |
| **Custom Actions** | `api/src/backend/api/v1/views.py` | `@action(detail=True)` patterns |
| **Filters** | `api/src/backend/api/filters.py` | `BaseProviderFilter`, `BaseScanProviderFilter`, `CommonFindingFilters` |

## Celery Tasks

| Pattern | File Path | Key Classes/Functions |
|---------|-----------|----------------------|
| **Task Definitions** | `api/src/backend/tasks/tasks.py` | All `@shared_task` definitions |
| **RLS Task Base** | `api/src/backend/config/celery.py` | `RLSTask` base class (creates APITask on dispatch) |
| **Task Decorators** | `api/src/backend/api/decorators.py` | `@set_tenant`, `@handle_provider_deletion` |
| **Celery Config** | `api/src/backend/config/celery.py` | Celery app, broker settings, visibility timeout |
| **Django Settings** | `api/src/backend/config/settings/celery.py` | `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` |
| **Beat Schedule** | `api/src/backend/tasks/beat.py` | `schedule_provider_scan()`, `PeriodicTask` creation |
| **Task Utilities** | `api/src/backend/tasks/utils.py` | `batched()`, `get_next_execution_datetime()` |

### Task Jobs (Business Logic)

| Job File | Purpose |
|----------|---------|
| `tasks/jobs/scan.py` | `perform_prowler_scan()`, `aggregate_findings()`, `aggregate_attack_surface()` |
| `tasks/jobs/deletion.py` | `delete_provider()`, `delete_tenant()` |
| `tasks/jobs/backfill.py` | Historical data backfill operations |
| `tasks/jobs/export.py` | Output file generation (CSV, JSON, HTML) |
| `tasks/jobs/report.py` | PDF report generation (ThreatScore, ENS, NIS2) |
| `tasks/jobs/connection.py` | Provider/integration connection checks |
| `tasks/jobs/integrations.py` | S3, Security Hub, Jira uploads |
| `tasks/jobs/muting.py` | Historical findings muting |
| `tasks/jobs/attack_paths/` | Attack paths scan (Neo4j/Cartography) |

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

## Tests

| Type | Path |
|------|------|
| **Central Fixtures** | `api/src/backend/conftest.py` |
| **API Tests** | `api/src/backend/api/tests/` |
| **Integration Tests** | `api/src/backend/api/tests/integration/` |
| **Task Tests** | `api/src/backend/tasks/tests/` |

## Related Skills

- **Generic DRF patterns**: Use `django-drf` skill for ViewSets, Serializers, Filters, JSON:API
- **API Testing**: Use `prowler-test-api` skill for testing patterns
