---
name: prowler-api
description: >
  Prowler API patterns: RLS, RBAC, providers, Celery tasks, SSE.
  Trigger: When working in api/ on models/serializers/viewsets/filters/tasks involving tenant isolation (RLS), RBAC, provider lifecycle, Celery tasks or SSE endpoints.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.3.0"
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
- Multi-database architecture (primary, replica, admin)
- Server-Sent Events (SSE) endpoints

For **generic DRF patterns** (ViewSets, Serializers, Filters, JSON:API), use `django-drf` skill.

All paths below are relative to `api/src/backend/` unless they start with `api/`.

---

## Critical Rules

- ALWAYS use `rls_transaction(tenant_id)` when querying tenant data outside a ViewSet (tasks, jobs, management commands)
- ALWAYS take `tenant_id` from the auth token (`request.tenant_id`), NEVER from `request.data`
- ALWAYS pass `tenant_id` to `get_role(user, tenant_id)`; inside `BaseRLSViewSet` use the cached `self.user_role`
- ALWAYS use explicit through models (inheriting `RowLevelSecurityProtectedModel`) for M2M relationships
- ALWAYS give Celery tasks a `name=`; route with `queue=` (omitted = default `celery` queue)
- ALWAYS call tasks with keyword arguments (`tenant_id=...`): the decorators read `kwargs`
- NEVER access `Provider.objects` (or any tenant model) in Celery without RLS context
- NEVER combine plain `@set_tenant` with `@handle_provider_deletion`: `@set_tenant` pops `tenant_id`, which `@handle_provider_deletion` needs. Use `@set_tenant(keep_tenant=True)`
- NEVER use `MainRouter.admin_db` unless it is an auth or cross-tenant admin operation (it bypasses RLS)

> `rls_transaction(value, parameter=POSTGRES_TENANT_VAR, using=None, retry_on_replica=True)` validates that `value` is a UUID (UUID objects and strings both work) and raises `ValidationError` otherwise.

---

## Architecture Overview

### Databases (`config/django/{devel,production,testing}.py`)

| Alias | DB user | Purpose | RLS |
|-------|---------|---------|-----|
| `default` | `POSTGRES_USER` (`default` = the `prowler_user` entry) | Standard API queries | **Yes** |
| `admin` | `POSTGRES_ADMIN_USER` | Migrations, auth lookups, Django internal tables | No |
| `replica` | `POSTGRES_REPLICA_USER` | Read-only queries | **Yes** |
| `admin_replica` | `POSTGRES_ADMIN_USER` | Admin reads on replica | No |
| `neo4j` | `NEO4J_USER` | Graph DB for Attack Paths (not routed by Django) | - |

```python
from api.db_router import MainRouter, READ_REPLICA_ALIAS

User.objects.using(MainRouter.admin_db).get(id=user_id)  # Auth lookups (bypasses RLS)

with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):  # Read-heavy task code
    Finding.objects.filter(scan_id=scan_id).count()
```

- `MainRouter.allow_migrate()` only allows `admin`: run `manage.py migrate --database admin`.
- `READ_REPLICA_ALIAS` is `None` without a replica; `rls_transaction` then uses `default`.
- Replica failures retry (`POSTGRES_REPLICA_MAX_ATTEMPTS`, default 3) and then fall back to primary.

### RLS Request Flow (`api/base_views.py`)

```text
Request -> BaseRLSViewSet.dispatch()  replica for SAFE_METHODS (if configured), transaction.atomic
        -> BaseRLSViewSet.initial()   tenant_id from request.auth (JWT or API key)
                                      rls_transaction(tenant_id) -> set_config('api.tenant_id', ...)
        -> queries are tenant-scoped; serializer context gets tenant_id
```

Other bases in the same file: `BaseTenantViewset` (tenant CRUD), `BaseUserViewset` (user endpoints), `BaseViewSet` (no RLS).

---

## Implementation Checklist

| # | Pattern | Reference | Key Points |
|---|---------|-----------|------------|
| 1 | **RLS Models** | `api/rls.py` | Inherit `RowLevelSecurityProtectedModel`, add `RowLevelSecurityConstraint` |
| 2 | **RLS Transactions** | `api/db_utils.py` | `rls_transaction(tenant_id)` context manager |
| 3 | **RBAC Permissions** | `api/rbac/permissions.py` | `Permissions` enum, `HasPermissions`, `get_role()`, `get_providers()` |
| 4 | **Provider Validation** | `api/models.py` | `validate_<provider>_uid()` staticmethods on `Provider` |
| 5 | **Celery Tasks** | `tasks/tasks.py`, `api/decorators.py`, `config/celery.py` | `@shared_task(base=RLSTask, name=...)`, `@set_tenant`, `@handle_provider_deletion` |
| 6 | **Task business logic** | `tasks/jobs/*.py` | Keep `tasks.py` thin; logic lives in `jobs/` |
| 7 | **RLS Serializers** | `api/v1/serializers.py` | Inherit `RLSSerializer` to auto-inject `tenant_id` |
| 8 | **Base ViewSets** | `api/base_views.py` | `BaseRLSViewSet` for tenant-scoped resources |
| 9 | **SSE endpoints** | `api/sse/` | Subclass `BaseSSEViewSet`, build channels with `make_channel_name()` |
| 10 | **Changelog** | `api/changelog.d/` | Add a towncrier fragment, never edit `CHANGELOG.md` (see `prowler-changelog`) |

> **Full file paths**: See [references/file-locations.md](references/file-locations.md)

---

## Decision Trees

### Which Base Model?
```text
Tenant-scoped data           -> RowLevelSecurityProtectedModel
Global/shared data           -> models.Model + BaseSecurityConstraint (rare)
Partitioned time-series      -> PostgresPartitionedModel + RowLevelSecurityProtectedModel
Hide data of deleted providers -> objects = ActiveProviderManager(); all_objects = models.Manager()
```

### Which Manager?
```text
Normal queries           -> Model.objects (ActiveProviderManager filters out deleted providers)
Include deleted records  -> Model.all_objects
Celery task context      -> Must be inside rls_transaction() first
```

### Which Database?
```text
Standard API queries     -> default (automatic via ViewSet)
Read-only API requests   -> replica (automatic for SAFE_METHODS in BaseRLSViewSet)
Heavy reads in tasks     -> rls_transaction(tenant_id, using=READ_REPLICA_ALIAS)
Auth/admin operations    -> MainRouter.admin_db
Cross-tenant lookups     -> MainRouter.admin_db (use sparingly!)
```

### Which Celery Decorators?

`@set_tenant` sets `api.tenant_id` on the default connection inside `transaction.atomic`.

| Task needs | Pattern (real example in `tasks/tasks.py`) |
|------------|--------------------------------------------|
| RLS context, no `tenant_id` param | `@set_tenant` (`check_provider_connection_task`) |
| RLS context + `tenant_id` param + deletion handling | `@set_tenant(keep_tenant=True)` then `@handle_provider_deletion` (`generate_outputs_task`) |
| Job opens its own `rls_transaction` + deletion handling | `@handle_provider_deletion` only (`perform_scan_task`, `perform_scan_summary_task`) |

```python
@shared_task(base=RLSTask, name="scan-report", queue="scan-reports")
@set_tenant(keep_tenant=True)
@handle_provider_deletion
def generate_outputs_task(scan_id: str, provider_id: str, tenant_id: str):
    ...
```

`@handle_provider_deletion` converts DB errors into `ProviderDeletedException` when the provider (looked up via `provider_id` or `scan_id` kwarg) was deleted mid-task.

---

## RLS Model Pattern

```python
from api.rls import RowLevelSecurityConstraint, RowLevelSecurityProtectedModel

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
    tags = models.ManyToManyField(ResourceTag, through="ResourceTagMapping")

class ResourceTagMapping(RowLevelSecurityProtectedModel):
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    tag = models.ForeignKey(ResourceTag, on_delete=models.CASCADE)

    class Meta(RowLevelSecurityProtectedModel.Meta):
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

Real code: `ProviderViewSet.connection` in `api/v1/views.py`.

```python
@action(detail=True, methods=["post"], url_name="connection")
def connection(self, request, pk=None):
    self.get_object()  # visibility check before queuing
    with transaction.atomic():
        task = check_provider_connection_task.delay(
            provider_id=pk, tenant_id=self.request.tenant_id
        )
    prowler_task = Task.objects.get(id=task.id)  # created by RLSTask.apply_async
    serializer = TaskSerializer(prowler_task)
    return Response(
        data=serializer.data,
        status=status.HTTP_202_ACCEPTED,
        headers={"Content-Location": reverse("task-detail", kwargs={"pk": prowler_task.id})},
    )
```

---

## Providers (16 in `Provider.ProviderChoices`)

| Provider | Value | UID Format |
|----------|-------|-----------|
| AWS | `aws` | 12 digits |
| Azure | `azure` | UUID v4 |
| GCP | `gcp` | 6-30 chars, lowercase, letter start (legacy `domain:project` allowed) |
| Kubernetes | `kubernetes` | 2-251 chars (context name or cluster ARN) |
| M365 | `m365` | Valid domain |
| GitHub | `github` | 1-39 chars, alphanumeric + hyphens |
| MongoDB Atlas | `mongodbatlas` | 24-char hex |
| IaC | `iac` | Repository URL |
| Oracle Cloud | `oraclecloud` | Tenancy OCID (`ocid1.…`) |
| Alibaba Cloud | `alibabacloud` | 16 digits |
| Cloudflare | `cloudflare` | 32-char lowercase hex |
| OpenStack | `openstack` | Project ID or name |
| Image | `image` | Container image reference |
| Google Workspace | `googleworkspace` | `C` + alphanumerics |
| Vercel | `vercel` | `team_` + 16-32 alphanumerics |
| Okta | `okta` | Okta-managed org domain (e.g. `acme.okta.com`) |

**Adding a new provider**:
1. Add to `Provider.ProviderChoices` and add a `validate_<value>_uid()` staticmethod (`Provider.clean()` dispatches with `getattr(self, f"validate_{self.provider}_uid")`).
2. Migration: `AlterField` on `provider.provider` + `RunSQL("ALTER TYPE provider ADD VALUE IF NOT EXISTS '<value>';", reverse_sql=migrations.RunSQL.noop)` (see `api/migrations/0093_okta_provider.py`).
3. Add a fragment in `api/changelog.d/`.

---

## RBAC Permissions (`api/rbac/permissions.py`)

| Permission | Controls |
|------------|----------|
| `MANAGE_USERS` | User CRUD, role assignments |
| `MANAGE_ACCOUNT` | Tenant settings |
| `MANAGE_BILLING` | Billing/subscription |
| `MANAGE_PROVIDERS` | Provider CRUD |
| `MANAGE_INTEGRATIONS` | Integration config |
| `MANAGE_SCANS` | Scan execution |
| `UNLIMITED_VISIBILITY` | See all providers (bypasses provider groups) |

- Views set `required_permissions` in `set_required_permissions()`. `HasPermissions` passes if, for each required permission, **any** of the user's roles in the tenant grants it (`get_user_roles()` + `roles_have_permissions()`).
- `get_role(user, tenant_id)` returns the **first** role in the tenant and raises `PermissionDenied` if none. It drives visibility, not permission checks.
- Revoking a task requires the permission mapped in `TASK_REVOKE_PERMISSIONS`; add new task names there.

### RBAC Visibility Pattern

```python
def get_queryset(self):
    role = self.user_role  # cached get_role(request.user, request.tenant_id)
    if role.unlimited_visibility:
        return Model.objects.filter(tenant_id=self.request.tenant_id)
    return Model.objects.filter(provider__in=get_providers(role))
```

Related helpers: `get_tasks(role)`, `get_integrations(...)`.

---

## Celery

### Queues (worker `-Q` list in `api/docker-entrypoint.sh`)

| Queue | Purpose |
|-------|---------|
| `celery` | Default (tasks without `queue=`: connection checks, orphan reconciliation) |
| `scans` | Prowler scan execution |
| `scan-reports` | Output generation (CSV, JSON-OCSF, HTML, compliance PDFs) |
| `overview` | Post-scan aggregations (summaries, severity, attack surface) |
| `compliance` | Compliance requirement rows and reports |
| `integrations` | S3, Security Hub, Jira |
| `deletion` | Provider/tenant deletion |
| `backfill` | Historical data backfills |
| `attack-paths-scans` | Attack Paths (Cartography/Neo4j) scans and cleanup |

A new queue must also be added to the `-Q` list in `api/docker-entrypoint.sh`, or no worker consumes it.

### Configuration (`config/celery.py`, `config/settings/celery.py`)

| Setting | Value | Purpose |
|---------|-------|---------|
| `visibility_timeout` | `DJANGO_BROKER_VISIBILITY_TIMEOUT` (86400) | Prevent re-queue of long tasks |
| `task_acks_late` + `task_reject_on_worker_lost` | `True` | Redeliver if a worker dies; scans opt out with `acks_late=False` |
| `worker_prefetch_multiplier` | `1` | One reserved task per worker |
| `task_time_limit` / `task_soft_time_limit` | 6h / 6h-10min (env overridable) | Global default limits |
| `task_annotations` | keyed by task name | 60s/120s for connection checks; 48h for scans and deletions |
| `CELERY_RESULT_BACKEND` | `django-db` | Results in PostgreSQL |
| `CELERY_TASK_TRACK_STARTED` | `True` | Track when tasks start |

Do not add a `"*"` entry to `task_annotations`: Celery applies it after per-task entries and overwrites them.

### Canvas, Beat, Enqueueing

- Post-scan workflow: `_perform_scan_complete_tasks()` in `tasks/tasks.py` (`chain` + `group` of `.si()` signatures).
- Daily scans: `schedule_provider_scan()` in `tasks/beat.py` (`IntervalSchedule` 24h, `PeriodicTask(task="scan-perform-scheduled", kwargs=json.dumps(...))`, first run with `countdown=5`). Beat uses `django_celery_beat.schedulers:DatabaseScheduler`.
- Enqueue after commit with `transaction.on_commit(...)` (see `enqueue_scan_execution_on_commit()` in `tasks/tasks.py`).

> **Examples:** See [assets/celery_patterns.py](assets/celery_patterns.py).

---

## SSE (Server-Sent Events)

`django-eventstream` over Valkey Pub/Sub (`config/settings/eventstream.py`, `EVENTSTREAM_VALKEY_DB`, default 2).

| Piece | Location | Rule |
|-------|----------|------|
| `BaseSSEViewSet` | `api/sse/base_views.py` | Subclass and override `get_channels()`; raise DRF exceptions on auth failure, never return an empty set |
| `make_channel_name(prefix, tenant_id, resource_id)` | `api/sse/utils.py` | Channel format `<prefix>:<tenant_id>:<resource_id>`; segments must not contain `:` |
| `SSEChannelManager` | `api/sse/channelmanager.py` | Drops channels whose tenant differs from the request tenant; re-checks membership on read; no replay buffer |

---

## UUIDv7 for Partitioned Tables

`Finding` and `ResourceFindingMapping` are `PostgresPartitionedModel`s range-partitioned on UUIDv7 `id`:

```python
from api.uuid_utils import datetime_to_uuid7, uuid7_end, uuid7_start

start = uuid7_start(datetime_to_uuid7(date_from))
end = uuid7_end(datetime_to_uuid7(date_to), settings.FINDINGS_TABLE_PARTITION_MONTHS)
queryset.filter(id__gte=start, id__lt=end)  # enables partition pruning
```

---

## Batch Operations with RLS (`api/db_utils.py`)

```python
from api.db_utils import batch_delete, create_objects_in_batches, update_objects_in_batches

batch_delete(tenant_id, queryset, batch_size=settings.DJANGO_DELETION_BATCH_SIZE)
create_objects_in_batches(tenant_id, Finding, objects, batch_size=500)
update_objects_in_batches(tenant_id, Finding, objects, fields=["status"], batch_size=500)
```

Each batch runs in its own `rls_transaction`.

---

## Security Patterns

> **Full examples**: See [assets/security_patterns.py](assets/security_patterns.py)

| Pattern | Rule |
|---------|------|
| **RLS in ViewSets** | Automatic via `BaseRLSViewSet` |
| **RLS in Celery** | `@set_tenant` or explicit `rls_transaction(tenant_id)` |
| **Never trust user input** | Use `request.tenant_id`, never `request.data.get("tenant_id")` |
| **Admin DB bypass** | Only for auth or cross-tenant admin ops: exposes ALL tenants' data |
| **Named tasks only** | NEVER send tasks by a name taken from user input |
| **Safe queuing** | `transaction.on_commit()` so the worker sees committed rows |
| **Idempotency** | `update_or_create` or idempotency keys (tasks are `acks_late` by default and may run twice) |

---

## Commands

```bash
# Run from api/src/backend (manage.py defaults to config.django.production; use your .env for devel)
cd api/src/backend && uv run python manage.py runserver
cd api/src/backend && uv run python manage.py migrate --database admin
cd api/src/backend && uv run python -m celery -A config.celery worker -l info -E
cd api/src/backend && uv run python -m celery -A config.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

# Tests (pytest.ini with config.django.testing lives in src/backend; needs PostgreSQL + Valkey;
# run in a shell without the dev .env loaded)
cd api/src/backend && uv run pytest -x --tb=short
cd api/src/backend && uv run pytest api/tests/test_views.py -k "provider"

# Lint/format from repo root (same ruff commands as .github/workflows/api-code-quality.yml)
make lint-api
make format-api

# Git hooks (prek, config in .pre-commit-config.yaml)
cd api && uv run prek run --all-files
```

---

## Resources

- **File Locations**: [references/file-locations.md](references/file-locations.md)
- **Modeling Decisions**: [references/modeling-decisions.md](references/modeling-decisions.md)
- **Configuration**: [references/configuration.md](references/configuration.md)
- **Production Hardening (generic Django)**: [references/production-settings.md](references/production-settings.md)
- **Security Patterns**: [assets/security_patterns.py](assets/security_patterns.py)
- **Celery Patterns**: [assets/celery_patterns.py](assets/celery_patterns.py)
- **Related skills**: `django-drf` (generic DRF), `prowler-test-api` (tests), `django-migration-psql` (migrations), `prowler-changelog` (changelog fragments)
