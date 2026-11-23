# Django-DRF File Locations

## Core API Files

| Pattern | File Path | Key Classes |
|---------|-----------|-------------|
| **Models** | `api/src/backend/api/models.py` | `Provider`, `Scan`, `Finding`, `Resource`, `StateChoices`, `StatusChoices` |
| **Base ViewSets** | `api/src/backend/api/base_views.py` | `BaseViewSet`, `BaseRLSViewSet`, `BaseTenantViewset`, `BaseUserViewset` |
| **ViewSets** | `api/src/backend/api/v1/views.py` | Concrete ViewSets, `CACHE_DECORATOR` |
| **ViewSet mixins** | `api/src/backend/api/v1/mixins.py` | `PaginateByPkMixin` |
| **Serializers** | `api/src/backend/api/v1/serializers.py` | `BaseModelSerializerV1`, `BaseWriteSerializer`, `RLSSerializer` |
| **Filters** | `api/src/backend/api/filters.py` | `BaseProviderFilter`, `BaseScanProviderFilter`, `CommonFindingFilters` |
| **URL Routing** | `api/src/backend/api/v1/urls.py` | Router setup, nested routes |
| **Pagination** | `drf_spectacular_jsonapi...JsonApiPageNumberPagination` (default), `api/src/backend/api/pagination.py` | `ComplianceOverviewPagination` |
| **Permissions / RBAC** | `api/src/backend/api/rbac/permissions.py` | `HasPermissions`, `Permissions` enum, `get_role(user, tenant_id)`, `get_providers()` |
| **Exceptions** | `api/src/backend/api/exceptions.py` | `custom_exception_handler`, `ModelValidationError`, `ConflictException` |
| **Settings** | `api/src/backend/config/django/base.py` | `REST_FRAMEWORK`, `SPECTACULAR_SETTINGS` |

## ViewSet Hierarchy

```text
BaseViewSet (minimal - no RLS/auth)
    │
    ├── BaseRLSViewSet (+ tenant filtering, RLS-protected models)
    │       └── Most ViewSets inherit this
    │
    ├── BaseTenantViewset (+ Tenant-specific logic)
    │       └── TenantViewSet
    │
    └── BaseUserViewset (+ User-specific logic)
            └── UserViewSet
```

## Serializer Hierarchy

```text
BaseModelSerializerV1 (JSON:API defaults, read_only_fields)
    │
    ├── RLSSerializer (auto-injects tenant_id from request)
    │       └── Most model serializers inherit this
    │
    └── BaseWriteSerializer (rejects unknown fields)
            └── Create/Update serializers
```

## Filter Hierarchy

```text
FilterSet (django-filter)
    │
    ├── CommonFindingFilters (mixin for date ranges, delta, status)
    │
    ├── BaseProviderFilter (FK to Provider: provider_id, provider_type, provider_groups)
    │
    ├── BaseScanProviderFilter (FK via Scan: same filters through scan__provider)
    │
    └── Resource-specific filters (ProviderFilter, ScanFilter, etc.)

Custom Filter Types:
  - UUIDInFilter: Comma-separated UUIDs
  - CharInFilter: Comma-separated strings
  - DateFilter: ISO date parsing
  - DateTimeFilter: ISO datetime parsing
```

## Testing Files

| Pattern | File Path | Key Classes |
|---------|-----------|-------------|
| **ViewSet Tests** | `api/src/backend/api/tests/test_views.py` | Test patterns, fixtures |
| **RBAC Tests** | `api/src/backend/api/tests/test_rbac.py` | Permission tests |
| **Serializer Tests** | `api/src/backend/api/tests/test_serializers.py` | Validation tests |
| **Conftest** | `api/src/backend/conftest.py` | Shared fixtures |

## Key Patterns

### Filter Usage

```python
# In filters.py
class ProviderFilter(FilterSet):
    class Meta:
        model = Provider
        fields = {
            "provider": ["exact", "in"],
            "connected": ["exact"],
        }

# Custom filter method
def filter_severity(self, queryset, name, value):
    if not value:
        return queryset
    return queryset.filter(severity__in=value)
```

### Serializer Usage

```python
# Read serializer
class ProviderSerializer(RLSSerializer):
    class Meta:
        model = Provider
        fields = ["id", "provider", "uid", "alias", "connected"]

# Write serializer
class ProviderCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Provider
        fields = ["provider", "uid", "alias"]
```

### ViewSet Action Pattern

```python
# Real: ProviderViewSet.connection in api/v1/views.py
@action(detail=True, methods=["post"], url_name="connection")
def connection(self, request, pk=None):
    self.get_object()
    with transaction.atomic():
        task = check_provider_connection_task.delay(provider_id=pk, tenant_id=self.request.tenant_id)
    prowler_task = Task.objects.get(id=task.id)
    return Response(
        data=TaskSerializer(prowler_task).data,
        status=status.HTTP_202_ACCEPTED,
        headers={"Content-Location": reverse("task-detail", kwargs={"pk": prowler_task.id})},
    )
```

## REST_FRAMEWORK Settings

Located in `api/src/backend/config/django/base.py` (excerpt):

```python
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular_jsonapi.schemas.openapi.JsonApiAutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": ("api.authentication.CombinedJWTOrAPIKeyAuthentication",),
    "PAGE_SIZE": 10,
    "EXCEPTION_HANDLER": "api.exceptions.custom_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "drf_spectacular_jsonapi.schemas.pagination.JsonApiPageNumberPagination",
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework_json_api.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ),
    "DEFAULT_RENDERER_CLASSES": ("api.renderers.APIJSONRenderer",),
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.backends.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "SEARCH_PARAM": "filter[search]",
    "JSON_API_UNIFORM_EXCEPTIONS": True,
    # ... more settings
}
```

## JSON:API Resource Names

Find all `JSONAPIMeta` declarations:
```bash
rg "resource_name" api/src/backend/api/models.py
```

Convention: kebab-case, plural (e.g., `provider-groups`, `mute-rules`)
