---
name: prowler-api
description: >
  Prowler API patterns: RLS, RBAC, 10 providers, SQL optimization, Celery.
  Trigger: When working on api/ - models, serializers, views, filters, tasks.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## Related Skills

- `prowler-test-api` - Testing patterns for API
- `django-drf` - Generic ViewSets, Serializers

---

## 1. Providers (10 Supported)

```python
class ProviderChoices(models.TextChoices):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    M365 = "m365"
    GITHUB = "github"
    MONGODBATLAS = "mongodbatlas"
    IAC = "iac"
    ORACLECLOUD = "oraclecloud"
    ALIBABACLOUD = "alibabacloud"
```

### UID Validation (Dynamic Dispatch)

Validation is called dynamically in `Provider.clean()`:

```python
def clean(self):
    super().clean()
    # Dynamically calls validate_aws_uid, validate_azure_uid, etc.
    getattr(self, f"validate_{self.provider}_uid")(self.uid)
```

**All validation methods are `@staticmethod` on `Provider` model:**

| Provider | Method | Format | Example |
|----------|--------|--------|---------|
| AWS | `validate_aws_uid` | 12 digits | `123456789012` |
| Azure | `validate_azure_uid` | UUID v4 | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| GCP | `validate_gcp_uid` | 6-30 chars, lowercase, starts with letter | `my-gcp-project-123` |
| M365 | `validate_m365_uid` | Valid domain | `contoso.onmicrosoft.com` |
| Kubernetes | `validate_kubernetes_uid` | 2-251 chars, alphanumeric with `._@:/-` | `arn:aws:eks:us-east-1:123456789012:cluster/my-cluster` |
| GitHub | `validate_github_uid` | 1-39 chars, GitHub username format | `my-org` |
| IaC | `validate_iac_uid` | Git repository URL | `https://github.com/user/repo.git` |
| Oracle Cloud | `validate_oraclecloud_uid` | OCID format | `ocid1.tenancy.oc1..aaa...` |
| MongoDB Atlas | `validate_mongodbatlas_uid` | 24-char hex | `507f1f77bcf86cd799439011` |
| Alibaba Cloud | `validate_alibabacloud_uid` | 16 digits | `1234567890123456` |

### Adding New Providers

When adding a new provider:

1. Add to `ProviderChoices` enum
2. Create `validate_<provider>_uid(value)` static method on `Provider` model
3. The UID format depends on how the cloud provider identifies accounts/projects:
   - **Ask the user**: "What is the UID format for this provider?" (account ID, project ID, org ID, etc.)
   - Check the provider's official documentation for the identifier format
   - Use regex that matches the exact format (e.g., `^\d{12}$` for AWS 12-digit account ID)

---

## 2. Row-Level Security (RLS)

### rls_transaction Context Manager

```python
from api.db_utils import rls_transaction

# ALWAYS use for tenant-scoped queries
with rls_transaction(tenant_id):
    providers = Provider.objects.filter(connected=True)
    # PostgreSQL enforces: WHERE tenant_id = current_setting('api.tenant_id')
```

### RLS Constraint on Models

```python
from api.rls import RowLevelSecurityProtectedModel, RowLevelSecurityConstraint

class Resource(RowLevelSecurityProtectedModel):
    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "resources"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
```

---

## 3. Managers (objects vs all_objects)

```python
class ActiveProviderManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(self.active_provider_filter())

    def active_provider_filter(self):
        if self.model is Provider:
            return Q(is_deleted=False)
        elif self.model in [Finding, ComplianceOverview, ScanSummary]:
            return Q(scan__provider__is_deleted=False)
        else:
            return Q(provider__is_deleted=False)

class Provider(RowLevelSecurityProtectedModel):
    objects = ActiveProviderManager()  # Excludes soft-deleted
    all_objects = models.Manager()     # All records
```

**Usage:**
```python
Provider.objects.all()       # Only is_deleted=False
Provider.all_objects.all()   # All including deleted

Finding.objects.all()        # Only from active provider scans
Finding.all_objects.all()    # All findings
```

---

## 4. RBAC (Role-Based Access Control)

### Permissions Enum

```python
from enum import Enum

class Permissions(Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ACCOUNT = "manage_account"
    MANAGE_BILLING = "manage_billing"
    MANAGE_PROVIDERS = "manage_providers"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_SCANS = "manage_scans"
    UNLIMITED_VISIBILITY = "unlimited_visibility"
```

### get_role() - Returns First Role Only

```python
def get_role(user: User) -> Optional[Role]:
    """Returns user's FIRST role, not aggregate."""
    return user.roles.first()
```

### get_providers() - Providers Accessible by Role

```python
def get_providers(role: Role) -> QuerySet[Provider]:
    """Returns providers from role's provider_groups."""
    provider_groups = role.provider_groups.all()
    if not provider_groups.exists():
        return Provider.objects.none()

    return Provider.objects.filter(
        tenant_id=role.tenant_id,
        provider_groups__in=provider_groups
    ).distinct()
```

### ViewSet RBAC Pattern

```python
from api.rbac.permissions import Permissions, get_providers, get_role

class ProviderViewSet(BaseRLSViewSet):
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def get_queryset(self):
        user_roles = get_role(self.request.user)

        if user_roles.unlimited_visibility:
            # Admin: sees all in tenant
            queryset = Provider.objects.filter(tenant_id=self.request.tenant_id)
        else:
            # Limited: filter by provider groups
            queryset = get_providers(user_roles)

        return queryset.select_related("secret").prefetch_related("provider_groups")
```

### HasPermissions Class (DRF Permission)

```python
class HasPermissions(BasePermission):
    def has_permission(self, request, view):
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions:
            return True

        user_roles = User.objects.using(MainRouter.admin_db).get(id=request.user.id).roles.all()
        if not user_roles:
            return False

        for perm in required_permissions:
            if not getattr(user_roles[0], perm.value, False):
                return False
        return True
```

---

## 5. SQL Optimization

### UUIDv7 Partitioning (Finding Table)

```python
from uuid6 import uuid7
from psqlextra.models import PostgresPartitionedModel
from psqlextra.types import PostgresPartitioningMethod

class Finding(PostgresPartitionedModel, RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid7)

    class PartitioningMeta:
        method = PostgresPartitioningMethod.RANGE
        key = ["id"]
```

### Index Best Practices

```python
class Meta:
    indexes = [
        # tenant_id FIRST for RLS efficiency
        models.Index(fields=["tenant_id", "provider_id"], name="res_tenant_prov_idx"),

        # Partial index for common filters
        models.Index(
            fields=["tenant_id", "id"],
            name="find_delta_new_idx",
            condition=Q(delta="new"),
        ),

        # GIN for arrays and full-text
        GinIndex(fields=["text_search"], name="res_search_gin_idx"),
        GinIndex(fields=["resource_regions"], name="find_regions_gin_idx"),
    ]
```

### prefetch_for_includes Pattern

```python
class ResourceViewSet(BaseRLSViewSet):
    prefetch_for_includes = {
        "__all__": [],
        "findings": [
            Prefetch("findings", queryset=Finding.all_objects.defer("raw_result"))
        ],
        "tags": [Prefetch("tags", queryset=ResourceTag.objects.all())],
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        includes = self.request.query_params.get("include", "").split(",")

        for include in includes:
            if include in self.prefetch_for_includes:
                queryset = queryset.prefetch_related(*self.prefetch_for_includes[include])
        return queryset
```

---

## 6. Celery Tasks

### Task with RLS Decorators

```python
from celery import shared_task
from config.celery import RLSTask
from api.decorators import set_tenant, handle_provider_deletion

@shared_task(base=RLSTask, name="scan-perform", queue="scans")
@set_tenant  # Pops tenant_id, sets PostgreSQL RLS config
@handle_provider_deletion  # Catches ObjectDoesNotExist if provider deleted
def perform_scan_task(tenant_id: str, scan_id: str, provider_id: str):
    """
    @set_tenant: Extracts tenant_id, calls set_config('api.tenant_id', ...)
    @handle_provider_deletion: Re-raises as ProviderDeletedException
    Note: Many tasks use only one decorator. Check existing tasks for patterns.
    """
    pass
```

### Task Queues

Check `tasks/tasks.py` for existing queues. Common ones: `scans`, `overview`, `compliance`, `deletion`, `integrations`. New queues can be added as needed.

### Task Orchestration

```python
from celery import chain, group

chain(
    perform_scan_summary_task.si(tenant_id=tenant_id, scan_id=scan_id),
    group(
        aggregate_daily_severity_task.si(tenant_id=tenant_id, ...),
        generate_outputs_task.si(tenant_id=tenant_id, ...),
    ),
).apply_async()
```

---

## 7. Serializers

### Naming Convention

```python
ProviderSerializer          # Read (list/retrieve)
ProviderIncludeSerializer   # When included in relationships
ProviderCreateSerializer    # POST operations
ProviderUpdateSerializer    # PATCH operations
```

### RLSSerializer (Auto-injects tenant_id)

```python
class RLSSerializer(BaseModelSerializerV1):
    def create(self, validated_data):
        tenant_id = self.context.get("tenant_id")
        validated_data["tenant_id"] = tenant_id
        return super().create(validated_data)
```

---

## 8. JSON:API Format

```python
# Content-Type
"application/vnd.api+json"

# Request
{
    "data": {
        "type": "providers",
        "attributes": {"alias": "my-account", "provider": "aws", "uid": "123456789012"}
    }
}

# Response
{
    "data": {
        "type": "providers",
        "id": "uuid",
        "attributes": {...},
        "relationships": {"tenant": {"data": {"type": "tenants", "id": "uuid"}}}
    }
}
```

---

## Commands

```bash
# Run API server
cd api && poetry run python src/backend/manage.py runserver

# Run tests
cd api && poetry run pytest -x --tb=short

# Create migration
cd api && poetry run python src/backend/manage.py makemigrations

# Celery worker
cd api && poetry run celery -A config.celery worker -l info -Q scans,overview
```

---

## Resources

- **Templates**: See [assets/](assets/) for ViewSet, Serializer, Celery Task, and Filter templates
- **Testing**: See `prowler-test-api` skill

## Keywords

prowler api, django, drf, rls, json:api, celery, rbac, postgresql
