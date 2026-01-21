---
name: django-drf
description: >
  Django REST Framework patterns.
  Trigger: When implementing generic DRF APIs (ViewSets, serializers, routers, permissions, filtersets). For Prowler API specifics (RLS/RBAC/Providers), also use prowler-api.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
  scope: [root, api]
  auto_invoke:
    - "Creating ViewSets, serializers, or filters in api/"
    - "Implementing JSON:API endpoints"
    - "Adding DRF pagination or permissions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Critical Patterns

- ALWAYS separate serializers by operation: Read / Create / Update / Include
- ALWAYS use `filterset_class` for complex filtering (not `filterset_fields`)
- ALWAYS validate unknown fields in write serializers (inherit `BaseWriteSerializer`)
- ALWAYS use `select_related`/`prefetch_related` in `get_queryset()` to avoid N+1
- ALWAYS handle `swagger_fake_view` in `get_queryset()` for schema generation
- ALWAYS use `@extend_schema_field` for OpenAPI docs on `SerializerMethodField`
- NEVER put business logic in serializers - use services/utils
- NEVER use auto-increment PKs - use UUIDv4 or UUIDv7
- NEVER use trailing slashes in URLs (`trailing_slash=False`)

> **Note:** `swagger_fake_view` is specific to **drf-spectacular** for OpenAPI schema generation.

---

## Implementation Checklist

When implementing a new endpoint, review these patterns in order:

| # | Pattern | Reference | Key Points |
|---|---------|-----------|------------|
| 1 | **Models** | `api/models.py` | UUID PK, `inserted_at`/`updated_at`, `JSONAPIMeta.resource_name` |
| 2 | **ViewSets** | `api/base_views.py`, `api/v1/views.py` | Inherit `BaseRLSViewSet`, `get_queryset()` with N+1 prevention |
| 3 | **Serializers** | `api/v1/serializers.py` | Separate Read/Create/Update/Include, inherit `BaseWriteSerializer` |
| 4 | **Filters** | `api/filters.py` | Use `filterset_class`, inherit base filter classes |
| 5 | **Permissions** | `api/base_views.py` | `required_permissions`, `set_required_permissions()` |
| 6 | **Pagination** | `api/pagination.py` | Custom pagination class if needed |
| 7 | **URL Routing** | `api/v1/urls.py` | `trailing_slash=False`, kebab-case paths |
| 8 | **OpenAPI Schema** | `api/v1/views.py` | `@extend_schema_view` with drf-spectacular |
| 9 | **Tests** | `api/tests/test_views.py` | JSON:API content type, fixture patterns |

> **Full file paths**: See [references/file-locations.md](references/file-locations.md)

---

## Decision Trees

### Which Serializer?
```
GET list/retrieve → <Model>Serializer
POST create       → <Model>CreateSerializer
PATCH update      → <Model>UpdateSerializer
?include=...      → <Model>IncludeSerializer
```

### Which Base Serializer?
```
Read-only serializer   → BaseModelSerializerV1
Create with tenant_id  → RLSSerializer + BaseWriteSerializer (auto-injects tenant_id on create)
Update with validation → BaseWriteSerializer (tenant_id already exists on object)
Non-model data         → BaseSerializerV1
```

### Which Filter Base?
```
Direct FK to Provider  → BaseProviderFilter
FK via Scan           → BaseScanProviderFilter
No provider relation  → FilterSet
```

### Which Base ViewSet?
```
RLS-protected model  → BaseRLSViewSet (most common)
Tenant operations    → BaseTenantViewset
User operations      → BaseUserViewset
No RLS required      → BaseViewSet (rare)
```

### Resource Name Format?
```
Single word model     → plural lowercase           (Provider → providers)
Multi-word model      → plural lowercase kebab     (ProviderGroup → provider-groups)
Through/join model    → parent-child pattern       (UserRoleRelationship → user-roles)
Aggregation/overview  → descriptive kebab plural   (ComplianceOverview → compliance-overviews)
```

---

## Serializer Patterns

### Base Class Hierarchy

```python
# Read serializer (most common)
class ProviderSerializer(RLSSerializer):
    class Meta:
        model = Provider
        fields = ["id", "provider", "uid", "alias", "connected", "inserted_at"]

# Write serializer (validates unknown fields)
class ProviderCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Provider
        fields = ["provider", "uid", "alias"]

# Include serializer (sparse fields for ?include=)
class ProviderIncludeSerializer(RLSSerializer):
    class Meta:
        model = Provider
        fields = ["id", "alias"]  # Minimal fields
```

### SerializerMethodField with OpenAPI

```python
from drf_spectacular.utils import extend_schema_field

class ProviderSerializer(RLSSerializer):
    connection = serializers.SerializerMethodField(read_only=True)

    @extend_schema_field({
        "type": "object",
        "properties": {
            "connected": {"type": "boolean"},
            "last_checked_at": {"type": "string", "format": "date-time"},
        },
    })
    def get_connection(self, obj):
        return {
            "connected": obj.connected,
            "last_checked_at": obj.connection_last_checked_at,
        }
```

### Included Serializers (JSON:API)

```python
class ScanSerializer(RLSSerializer):
    included_serializers = {
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
    }
```

### Sensitive Data Masking

```python
def to_representation(self, instance):
    data = super().to_representation(instance)
    # Mask by default, expose only on explicit request
    fields_param = self.context.get("request").query_params.get("fields[my-model]", "")
    if "api_key" in fields_param:
        data["api_key"] = instance.api_key_decoded
    else:
        data["api_key"] = "****" if instance.api_key else None
    return data
```

---

## ViewSet Patterns

### get_queryset() with N+1 Prevention

**Always combine** `swagger_fake_view` check with `select_related`/`prefetch_related`:

```python
def get_queryset(self):
    # REQUIRED: Return empty queryset for OpenAPI schema generation
    if getattr(self, "swagger_fake_view", False):
        return Provider.objects.none()

    # N+1 prevention: eager load relationships
    return Provider.objects.select_related(
        "tenant",
    ).prefetch_related(
        "provider_groups",
        Prefetch("tags", queryset=ProviderTag.objects.filter(tenant_id=self.request.tenant_id)),
    )
```

> **Why swagger_fake_view?** drf-spectacular introspects ViewSets to generate OpenAPI schemas. Without this check, it executes real queries and can fail without request context.

### Action-Specific Serializers

```python
def get_serializer_class(self):
    if self.action == "create":
        return ProviderCreateSerializer
    elif self.action == "partial_update":
        return ProviderUpdateSerializer
    elif self.action in ["connection", "destroy"]:
        return TaskSerializer
    return ProviderSerializer
```

### Dynamic Permissions per Action

```python
class ProviderViewSet(BaseRLSViewSet):
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def set_required_permissions(self):
        if self.action in ["list", "retrieve"]:
            self.required_permissions = []  # Read-only = no permission
        else:
            self.required_permissions = [Permissions.MANAGE_PROVIDERS]
```

### Cache Decorator

```python
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
)

@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProviderViewSet(BaseRLSViewSet):
    pass
```

### Custom Actions

```python
# Detail action (operates on single object)
@action(detail=True, methods=["post"], url_name="connection")
def connection(self, request, pk=None):
    instance = self.get_object()
    # Process instance...

# List action (operates on collection)
@action(detail=False, methods=["get"], url_name="metadata")
def metadata(self, request):
    queryset = self.filter_queryset(self.get_queryset())
    # Aggregate over queryset...
```

---

## Filter Patterns

### Base Filter Classes

```python
class BaseProviderFilter(FilterSet):
    """For models with direct FK to Provider"""
    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(field_name="provider__provider", choices=Provider.ProviderChoices.choices)

class BaseScanProviderFilter(FilterSet):
    """For models with FK to Scan (Scan has FK to Provider)"""
    provider_id = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
```

### Custom Multi-Value Filters

```python
class UUIDInFilter(BaseInFilter, UUIDFilter):
    pass

class CharInFilter(BaseInFilter, CharFilter):
    pass

class ChoiceInFilter(BaseInFilter, ChoiceFilter):
    pass
```

### ArrayField Filtering

```python
# Single value contains
region = CharFilter(method="filter_region")

def filter_region(self, queryset, name, value):
    return queryset.filter(resource_regions__contains=[value])

# Multi-value overlap
region__in = CharInFilter(field_name="resource_regions", lookup_expr="overlap")
```

### Date Range Validation

```python
def filter_queryset(self, queryset):
    # Require date filter for performance
    if not (date_filters_provided):
        raise ValidationError([{
            "detail": "At least one date filter is required",
            "status": 400,
            "source": {"pointer": "/data/attributes/inserted_at"},
            "code": "required",
        }])

    # Validate max range
    if date_range > settings.FINDINGS_MAX_DAYS_IN_RANGE:
        raise ValidationError(...)

    return super().filter_queryset(queryset)
```

### Dynamic FilterSet Selection

```python
def get_filterset_class(self):
    if self.action in ["latest", "metadata_latest"]:
        return LatestFindingFilter
    return FindingFilter
```

### Enum Field Override

```python
class Meta:
    model = Finding
    filter_overrides = {
        FindingDeltaEnumField: {"filter_class": CharFilter},
        StatusEnumField: {"filter_class": CharFilter},
        SeverityEnumField: {"filter_class": CharFilter},
    }
```

---

## Performance Patterns

### PaginateByPkMixin

For large querysets with expensive joins:

```python
class PaginateByPkMixin:
    def paginate_by_pk(self, request, base_queryset, manager,
                       select_related=None, prefetch_related=None):
        # 1. Get PKs only (cheap)
        pk_list = base_queryset.values_list("id", flat=True)
        page = self.paginate_queryset(pk_list)

        # 2. Fetch full objects for just the page
        queryset = manager.filter(id__in=page)
        if select_related:
            queryset = queryset.select_related(*select_related)
        if prefetch_related:
            queryset = queryset.prefetch_related(*prefetch_related)

        # 3. Re-sort to preserve DB ordering
        queryset = sorted(queryset, key=lambda obj: page.index(obj.id))
        return self.get_paginated_response(self.get_serializer(queryset, many=True).data)
```

### Prefetch in Serializers

```python
def get_tags(self, obj):
    # Use prefetched tags if available
    if hasattr(obj, "prefetched_tags"):
        return {tag.key: tag.value for tag in obj.prefetched_tags}
    # Fallback (causes N+1 if not prefetched)
    return obj.get_tags(self.context.get("tenant_id"))
```

---

## Naming Conventions

| Entity | Pattern | Example |
|--------|---------|---------|
| Serializer (read) | `<Model>Serializer` | `ProviderSerializer` |
| Serializer (create) | `<Model>CreateSerializer` | `ProviderCreateSerializer` |
| Serializer (update) | `<Model>UpdateSerializer` | `ProviderUpdateSerializer` |
| Serializer (include) | `<Model>IncludeSerializer` | `ProviderIncludeSerializer` |
| Filter | `<Model>Filter` | `ProviderFilter` |
| ViewSet | `<Model>ViewSet` | `ProviderViewSet` |

---

## OpenAPI Documentation

```python
from drf_spectacular.utils import extend_schema, extend_schema_view

@extend_schema_view(
    list=extend_schema(tags=["Provider"], summary="List all providers"),
    retrieve=extend_schema(tags=["Provider"], summary="Retrieve provider"),
    create=extend_schema(tags=["Provider"], summary="Create provider"),
)
@extend_schema(tags=["Provider"])
class ProviderViewSet(BaseRLSViewSet):
    pass
```

---

## API Security Patterns

> **Full examples**: See [assets/security_patterns.py](assets/security_patterns.py)

| Pattern | Key Points |
|---------|------------|
| **Input Validation** | Use `validate_<field>()` for sanitization, `validate()` for cross-field |
| **Prevent Mass Assignment** | ALWAYS use explicit `fields` list, NEVER `__all__` or `exclude` |
| **Object-Level Permissions** | Implement `has_object_permission()` for ownership checks |
| **Rate Limiting** | Configure `DEFAULT_THROTTLE_RATES`, use per-view throttles for sensitive endpoints |
| **Prevent Info Disclosure** | Generic error messages, return 404 not 403 for unauthorized (prevents enumeration) |
| **SQL Injection** | ALWAYS use ORM parameterization, NEVER string interpolation in raw SQL |

### Quick Reference

```python
# Input validation in serializer
def validate_uid(self, value):
    value = value.strip().lower()
    if not re.match(r'^[a-z0-9-]+$', value):
        raise serializers.ValidationError("Invalid format")
    return value

# Explicit fields (prevent mass assignment)
class Meta:
    fields = ["name", "email"]  # GOOD: whitelist
    read_only_fields = ["id", "inserted_at"]  # System fields

# Object permission
class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.owner == request.user

# Throttling for sensitive endpoints
class BurstRateThrottle(UserRateThrottle):
    rate = "10/minute"

# Safe error messages (prevent enumeration)
def get_object(self):
    try:
        return super().get_object()
    except Http404:
        raise NotFound("Resource not found")  # Generic, no internal IDs
```

---

## Commands

```bash
# Development
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run python src/backend/manage.py shell

# Database
cd api && poetry run python src/backend/manage.py makemigrations
cd api && poetry run python src/backend/manage.py migrate

# Testing
cd api && poetry run pytest -x --tb=short
cd api && poetry run make lint
```

---

## Resources

### Local References
- **File Locations**: See [references/file-locations.md](references/file-locations.md)
- **JSON:API Conventions**: See [references/json-api-conventions.md](references/json-api-conventions.md)
- **Security Patterns**: See [assets/security_patterns.py](assets/security_patterns.py)

### Context7 MCP (Recommended)

**Prerequisite:** Install Context7 MCP server for up-to-date documentation lookup.

When implementing or debugging, query these libraries via `mcp_context7_query-docs`:

| Library | Context7 ID | Use For |
|---------|-------------|---------|
| **Django** | `/websites/djangoproject_en_5_2` | Models, ORM, migrations |
| **DRF** | `/websites/django-rest-framework` | ViewSets, serializers, permissions |
| **drf-spectacular** | `/tfranzel/drf-spectacular` | OpenAPI schema, `@extend_schema` |

**Example queries:**
```
mcp_context7_query-docs(libraryId="/websites/django-rest-framework", query="ViewSet get_queryset best practices")
mcp_context7_query-docs(libraryId="/tfranzel/drf-spectacular", query="extend_schema examples for custom actions")
mcp_context7_query-docs(libraryId="/websites/djangoproject_en_5_2", query="model constraints and indexes")
```

> **Note:** Use `mcp_context7_resolve-library-id` first if you need to find the correct library ID.

### External Docs
- **DRF Docs**: https://www.django-rest-framework.org/
- **DRF JSON:API**: https://django-rest-framework-json-api.readthedocs.io/
- **drf-spectacular**: https://drf-spectacular.readthedocs.io/
- **django-filter**: https://django-filter.readthedocs.io/
