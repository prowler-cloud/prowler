---
name: prowler-api
description: >
  Prowler API patterns: RLS, RBAC, providers, Celery tasks.
  Trigger: When working in api/ on models/serializers/viewsets/filters/tasks involving tenant isolation (RLS), RBAC, or provider lifecycle.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
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
- Multi-database architecture (4-database setup)

For **generic DRF patterns** (ViewSets, Serializers, Filters, JSON:API), use `django-drf` skill.

---

## Critical Rules

- ALWAYS use `rls_transaction(tenant_id)` when querying outside ViewSet context
- ALWAYS use `get_role()` before checking permissions (returns FIRST role only)
- ALWAYS use `@set_tenant` then `@handle_provider_deletion` decorator order
- ALWAYS use explicit through models for M2M relationships (required for RLS)
- NEVER access `Provider.objects` without RLS context in Celery tasks
- NEVER bypass RLS by using raw SQL or `connection.cursor()`
- NEVER use Django's default M2M - RLS requires through models with `tenant_id`

> **Note**: `rls_transaction()` accepts both UUID objects and strings - it converts internally via `str(value)`.

---

## Architecture Overview

### 4-Database Architecture

| Database | Alias | Purpose | RLS |
|----------|-------|---------|-----|
| `default` | `prowler_user` | Standard API queries | **Yes** |
| `admin` | `admin` | Migrations, auth bypass | No |
| `replica` | `prowler_user` | Read-only queries | **Yes** |
| `admin_replica` | `admin` | Admin read replica | No |

```python
# When to use admin (bypasses RLS)
from api.db_router import MainRouter
User.objects.using(MainRouter.admin_db).get(id=user_id)  # Auth lookups

# Standard queries use default (RLS enforced)
Provider.objects.filter(connected=True)  # Requires rls_transaction context
```

### RLS Transaction Flow

```
Request → Authentication → BaseRLSViewSet.initial()
                                    │
                                    ├─ Extract tenant_id from JWT
                                    ├─ SET api.tenant_id = 'uuid' (PostgreSQL)
                                    └─ All queries now tenant-scoped
```

---

## Implementation Checklist

When implementing Prowler-specific API features:

| # | Pattern | Reference | Key Points |
|---|---------|-----------|------------|
| 1 | **RLS Models** | `api/rls.py` | Inherit `RowLevelSecurityProtectedModel`, add constraint |
| 2 | **RLS Transactions** | `api/db_utils.py` | Use `rls_transaction(tenant_id)` context manager |
| 3 | **RBAC Permissions** | `api/rbac/permissions.py` | `get_role()`, `get_providers()`, `Permissions` enum |
| 4 | **Provider Validation** | `api/models.py` | `validate_<provider>_uid()` methods on `Provider` model |
| 5 | **Celery Tasks** | `tasks/tasks.py`, `api/decorators.py`, `config/celery.py` | Task definitions, decorators (`@set_tenant`, `@handle_provider_deletion`), `RLSTask` base |
| 6 | **RLS Serializers** | `api/v1/serializers.py` | Inherit `RLSSerializer` to auto-inject `tenant_id` |
| 7 | **Through Models** | `api/models.py` | ALL M2M must use explicit through with `tenant_id` |

> **Full file paths**: See [references/file-locations.md](references/file-locations.md)

---

## Decision Trees

### Which Base Model?
```
Tenant-scoped data       → RowLevelSecurityProtectedModel
Global/shared data       → models.Model + BaseSecurityConstraint (rare)
Partitioned time-series  → PostgresPartitionedModel + RowLevelSecurityProtectedModel
Soft-deletable           → Add is_deleted + ActiveProviderManager
```

### Which Manager?
```
Normal queries           → Model.objects (excludes deleted)
Include deleted records  → Model.all_objects
Celery task context      → Must use rls_transaction() first
```

### Which Database?
```
Standard API queries     → default (automatic via ViewSet)
Read-only operations     → replica (automatic for GET in BaseRLSViewSet)
Auth/admin operations    → MainRouter.admin_db
Cross-tenant lookups     → MainRouter.admin_db (use sparingly!)
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

## RLS Model Pattern

```python
from api.rls import RowLevelSecurityProtectedModel, RowLevelSecurityConstraint

class MyModel(RowLevelSecurityProtectedModel):
    # tenant FK inherited from parent
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=255)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "my_models"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "my-models"
```

### M2M Relationships (MUST use through models)

```python
class Resource(RowLevelSecurityProtectedModel):
    tags = models.ManyToManyField(
        ResourceTag,
        through="ResourceTagMapping",  # REQUIRED for RLS
    )

class ResourceTagMapping(RowLevelSecurityProtectedModel):
    # Through model MUST have tenant_id for RLS
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    tag = models.ForeignKey(ResourceTag, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
```

---

## Async Task Response Pattern (202 Accepted)

For long-running operations, return 202 with task reference:

```python
@action(detail=True, methods=["post"], url_name="connection")
def connection(self, request, pk=None):
    with transaction.atomic():
        task = check_provider_connection_task.delay(
            provider_id=pk, tenant_id=self.request.tenant_id
        )
    prowler_task = Task.objects.get(id=task.id)
    serializer = TaskSerializer(prowler_task)
    return Response(
        data=serializer.data,
        status=status.HTTP_202_ACCEPTED,
        headers={"Content-Location": reverse("task-detail", kwargs={"pk": prowler_task.id})}
    )
```

---

## Providers (11 Supported)

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

### RBAC Visibility Pattern

```python
def get_queryset(self):
    user_role = get_role(self.request.user)
    if user_role.unlimited_visibility:
        return Model.objects.filter(tenant_id=self.request.tenant_id)
    else:
        # Filter by provider_groups assigned to role
        return Model.objects.filter(provider__in=get_providers(user_role))
```

---

## Celery Queues

| Queue | Purpose |
|-------|---------|
| `scans` | Prowler scan execution |
| `overview` | Dashboard aggregations (severity, attack surface) |
| `compliance` | Compliance report generation |
| `integrations` | External integrations (Jira, S3, Security Hub) |
| `deletion` | Provider/tenant deletion (async) |
| `backfill` | Historical data backfill operations |
| `scan-reports` | Output generation (CSV, JSON, HTML, PDF) |

---

## Task Composition (Canvas)

Use Celery's Canvas primitives for complex workflows:

### Chain (Sequential)

```python
from celery import chain

# Tasks run sequentially: A → B → C
chain(
    task_a.si(tenant_id=tenant_id),
    task_b.si(tenant_id=tenant_id),
    task_c.si(tenant_id=tenant_id),
).apply_async()
```

### Group (Parallel)

```python
from celery import group

# Tasks run in parallel: A, B, C simultaneously
group(
    task_a.si(tenant_id=tenant_id),
    task_b.si(tenant_id=tenant_id),
    task_c.si(tenant_id=tenant_id),
).apply_async()
```

### Combined Patterns (Real Example)

```python
# From tasks/tasks.py - Post-scan workflow
chain(
    perform_scan_summary_task.si(tenant_id=tenant_id, scan_id=scan_id),
    group(
        aggregate_daily_severity_task.si(tenant_id=tenant_id, scan_id=scan_id),
        generate_outputs_task.si(scan_id=scan_id, provider_id=provider_id, tenant_id=tenant_id),
    ),
    group(
        generate_compliance_reports_task.si(tenant_id=tenant_id, scan_id=scan_id, provider_id=provider_id),
        check_integrations_task.si(tenant_id=tenant_id, provider_id=provider_id, scan_id=scan_id),
    ),
).apply_async()
```

> **Note:** Use `.si()` (signature immutable) to prevent result passing between tasks. Use `.s()` if you need to pass results.

---

## Beat Scheduling (Periodic Tasks)

### Creating a Scheduled Task

```python
import json
from datetime import datetime, timedelta, timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask

# 1. Create or get the schedule
schedule, _ = IntervalSchedule.objects.get_or_create(
    every=24,
    period=IntervalSchedule.HOURS,
)

# 2. Create the periodic task
periodic_task = PeriodicTask.objects.create(
    interval=schedule,
    name=f"scan-perform-scheduled-{provider_id}",  # Unique name
    task="scan-perform-scheduled",  # Task name (not function name)
    kwargs=json.dumps({
        "tenant_id": str(tenant_id),
        "provider_id": str(provider_id),
    }),
    one_off=False,
    start_time=datetime.now(timezone.utc) + timedelta(hours=24),
)
```

### Deleting a Scheduled Task

```python
PeriodicTask.objects.filter(name=f"scan-perform-scheduled-{provider_id}").delete()
```

### Avoiding Race Conditions

```python
# Use countdown to ensure DB transaction commits before task runs
perform_scheduled_scan_task.apply_async(
    kwargs={"tenant_id": tenant_id, "provider_id": provider_id},
    countdown=5,  # Wait 5 seconds
)
```

---

## Advanced Task Patterns

### Accessing Task Metadata with `bind=True`

```python
@shared_task(base=RLSTask, bind=True, name="scan-perform-scheduled", queue="scans")
def perform_scheduled_scan_task(self, tenant_id: str, provider_id: str):
    task_id = self.request.id  # Current task ID
    retries = self.request.retries  # Number of retries so far

    # Use task_id for tracking
    scan_instance.task_id = task_id
    scan_instance.save()
```

### Logging with `get_task_logger`

```python
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

@shared_task(base=RLSTask, name="my-task")
@set_tenant
def my_task(provider_id: str):
    # tenant_id is NOT in signature - @set_tenant pops it from kwargs
    # but RLS context is already set by the decorator
    logger.info(f"Processing provider {provider_id}")
    logger.warning("Potential issue detected")
    logger.error("Failed to process")

# Call with tenant_id in kwargs (decorator handles it)
my_task.delay(provider_id="...", tenant_id="...")
```

### Handling `SoftTimeLimitExceeded`

```python
from celery.exceptions import SoftTimeLimitExceeded

@shared_task(
    base=RLSTask,
    soft_time_limit=300,  # 5 minutes - raises SoftTimeLimitExceeded
    time_limit=360,       # 6 minutes - kills task (SIGKILL)
)
@set_tenant(keep_tenant=True)  # keep_tenant=True to pass tenant_id to function
def long_running_task(tenant_id: str, scan_id: str):
    try:
        for batch in large_dataset:
            process_batch(batch)
    except SoftTimeLimitExceeded:
        logger.warning(f"Task soft limit exceeded for scan {scan_id}, saving progress...")
        save_partial_progress(scan_id)
        raise  # Re-raise to mark task as failed
```

### `@set_tenant` Behavior

| Mode | `tenant_id` in kwargs | `tenant_id` passed to function |
|------|----------------------|-------------------------------|
| `@set_tenant` (default) | Popped (removed) | NO - function doesn't receive it |
| `@set_tenant(keep_tenant=True)` | Read but kept | YES - function receives it |

```python
# Example: @set_tenant (default) - tenant_id NOT in function signature
@shared_task(base=RLSTask, name="provider-connection-check")
@set_tenant
def check_provider_connection_task(provider_id: str):  # No tenant_id param
    return check_provider_connection(provider_id=provider_id)

# Example: @set_tenant(keep_tenant=True) - tenant_id IN function signature
@shared_task(base=RLSTask, name="scan-report", queue="scan-reports")
@set_tenant(keep_tenant=True)
def generate_outputs_task(scan_id: str, provider_id: str, tenant_id: str):  # Has tenant_id
    # tenant_id available for use inside the function
    pass
```

### Deferred Execution with `countdown` and `eta`

```python
# Execute after 30 seconds
my_task.apply_async(kwargs={...}, countdown=30)

# Execute at specific time
from datetime import datetime, timezone
my_task.apply_async(
    kwargs={...},
    eta=datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)
)
```

---

## Celery Configuration

### Broker Settings (config/celery.py)

```python
from celery import Celery

celery_app = Celery("tasks")
celery_app.config_from_object("django.conf:settings", namespace="CELERY")

# Visibility timeout - CRITICAL for long-running tasks
# If task takes longer than this, broker assumes worker died and re-queues
BROKER_VISIBILITY_TIMEOUT = 86400  # 24 hours for scan tasks

celery_app.conf.broker_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}
celery_app.conf.result_backend_transport_options = {
    "visibility_timeout": BROKER_VISIBILITY_TIMEOUT
}

# Result settings
celery_app.conf.update(
    result_extended=True,   # Store additional task metadata
    result_expires=None,    # Never expire results (we manage cleanup)
)
```

### Django Settings (config/settings/celery.py)

```python
CELERY_BROKER_URL = f"redis://{VALKEY_HOST}:{VALKEY_PORT}/{VALKEY_DB}"
CELERY_RESULT_BACKEND = "django-db"  # Store results in PostgreSQL  # trufflehog:ignore
CELERY_TASK_TRACK_STARTED = True     # Track when tasks start
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
```

### Global Time Limits (Optional)

```python
# In settings.py - applies to ALL tasks
CELERY_TASK_SOFT_TIME_LIMIT = 3600   # 1 hour soft limit
CELERY_TASK_TIME_LIMIT = 3660        # 1 hour + 1 minute hard limit
```

---

## UUIDv7 for Partitioned Tables

`Finding` and `ResourceFindingMapping` use UUIDv7 for time-based partitioning:

```python
from uuid6 import uuid7
from api.uuid_utils import uuid7_start, uuid7_end, datetime_to_uuid7

# Partition-aware filtering
start = uuid7_start(datetime_to_uuid7(date_from))
end = uuid7_end(datetime_to_uuid7(date_to), settings.FINDINGS_TABLE_PARTITION_MONTHS)
queryset.filter(id__gte=start, id__lt=end)
```

**Why UUIDv7?** Time-ordered UUIDs enable PostgreSQL to prune partitions during range queries.

---

## Batch Operations with RLS

```python
from api.db_utils import batch_delete, create_objects_in_batches, update_objects_in_batches

# Delete in batches (RLS-aware)
batch_delete(tenant_id, queryset, batch_size=1000)

# Bulk create with RLS
create_objects_in_batches(tenant_id, Finding, objects, batch_size=500)

# Bulk update with RLS
update_objects_in_batches(tenant_id, Finding, objects, fields=["status"], batch_size=500)
```

---

## Security Patterns

> **Full examples**: See [assets/security_patterns.py](assets/security_patterns.py)

### Tenant Isolation Summary

| Pattern | Rule |
|---------|------|
| **RLS in ViewSets** | Automatic via `BaseRLSViewSet` - tenant_id from JWT |
| **RLS in Celery** | MUST use `@set_tenant` + `rls_transaction(tenant_id)` |
| **Cross-tenant validation** | Defense-in-depth: verify `obj.tenant_id == request.tenant_id` |
| **Never trust user input** | Use `request.tenant_id` from JWT, never `request.data.get("tenant_id")` |
| **Admin DB bypass** | Only for cross-tenant admin ops - exposes ALL tenants' data |

### Celery Task Security Summary

| Pattern | Rule |
|---------|------|
| **Named tasks only** | NEVER use dynamic task names from user input |
| **Validate arguments** | Check UUID format before database queries |
| **Safe queuing** | Use `transaction.on_commit()` to enqueue AFTER commit |
| **Modern retries** | Use `autoretry_for`, `retry_backoff`, `retry_jitter` |
| **Time limits** | Set `soft_time_limit` and `time_limit` to prevent hung tasks |
| **Idempotency** | Use `update_or_create` or idempotency keys |

### Quick Reference

```python
# Safe task queuing - task only enqueued after transaction commits
with transaction.atomic():
    provider = Provider.objects.create(**data)
    transaction.on_commit(
        lambda: verify_provider_connection.delay(
            tenant_id=str(request.tenant_id),
            provider_id=str(provider.id)
        )
    )

# Modern retry pattern
@shared_task(
    base=RLSTask,
    bind=True,
    autoretry_for=(ConnectionError, TimeoutError, OperationalError),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=5,
    soft_time_limit=300,
    time_limit=360,
)
@set_tenant
def sync_provider_data(self, tenant_id, provider_id):
    with rls_transaction(tenant_id):
        # ... task logic
        pass

# Idempotent task - safe to retry
@shared_task(base=RLSTask, acks_late=True)
@set_tenant
def process_finding(tenant_id, finding_uid, data):
    with rls_transaction(tenant_id):
        Finding.objects.update_or_create(uid=finding_uid, defaults=data)
```

---

## Production Deployment Checklist

> **Full settings**: See [references/production-settings.md](references/production-settings.md)

Run before every production deployment:

```bash
cd api && poetry run python src/backend/manage.py check --deploy
```

### Critical Settings

| Setting | Production Value | Risk if Wrong |
|---------|-----------------|---------------|
| `DEBUG` | `False` | Exposes stack traces, settings, SQL queries |
| `SECRET_KEY` | Env var, rotated | Session hijacking, CSRF bypass |
| `ALLOWED_HOSTS` | Explicit list | Host header attacks |
| `SECURE_SSL_REDIRECT` | `True` | Credentials sent over HTTP |
| `SESSION_COOKIE_SECURE` | `True` | Session cookies over HTTP |
| `CSRF_COOKIE_SECURE` | `True` | CSRF tokens over HTTP |
| `SECURE_HSTS_SECONDS` | `31536000` (1 year) | Downgrade attacks |
| `CONN_MAX_AGE` | `60` or higher | Connection pool exhaustion |

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

# Production checks
cd api && poetry run python src/backend/manage.py check --deploy
```

---

## Resources

### Local References
- **File Locations**: See [references/file-locations.md](references/file-locations.md)
- **Modeling Decisions**: See [references/modeling-decisions.md](references/modeling-decisions.md)
- **Configuration**: See [references/configuration.md](references/configuration.md)
- **Production Settings**: See [references/production-settings.md](references/production-settings.md)
- **Security Patterns**: See [assets/security_patterns.py](assets/security_patterns.py)

### Related Skills
- **Generic DRF Patterns**: Use `django-drf` skill
- **API Testing**: Use `prowler-test-api` skill

### Context7 MCP (Recommended)

**Prerequisite:** Install Context7 MCP server for up-to-date documentation lookup.

When implementing or debugging Prowler-specific patterns, query these libraries via `mcp_context7_query-docs`:

| Library | Context7 ID | Use For |
|---------|-------------|---------|
| **Celery** | `/websites/celeryq_dev_en_stable` | Task patterns, queues, error handling |
| **django-celery-beat** | `/celery/django-celery-beat` | Periodic task scheduling |
| **Django** | `/websites/djangoproject_en_5_2` | Models, ORM, constraints, indexes |

**Example queries:**
```
mcp_context7_query-docs(libraryId="/websites/celeryq_dev_en_stable", query="shared_task decorator retry patterns")
mcp_context7_query-docs(libraryId="/celery/django-celery-beat", query="periodic task database scheduler")
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_2", query="model constraints CheckConstraint UniqueConstraint")
```

> **Note:** Use `mcp_context7_resolve-library-id` first if you need to find the correct library ID.
