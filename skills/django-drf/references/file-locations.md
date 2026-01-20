# Django-DRF File Locations

## Core API Files

| Pattern | File Path | Key Classes |
|---------|-----------|-------------|
| **Models** | `api/src/backend/api/models.py` | `Provider`, `Scan`, `Finding`, `Resource`, `StateChoices`, `StatusChoices` |
| **ViewSets** | `api/src/backend/api/v1/views.py` | `BaseViewSet`, `BaseRLSViewSet`, `BaseTenantViewset`, `BaseUserViewset` |
| **Serializers** | `api/src/backend/api/v1/serializers.py` | `BaseModelSerializerV1`, `BaseWriteSerializer`, `RLSSerializer` |
| **Filters** | `api/src/backend/api/filters.py` | `BaseProviderFilter`, `BaseScanProviderFilter`, `CommonFindingFilters` |
| **URL Routing** | `api/src/backend/api/v1/urls.py` | Router setup, nested routes |
| **Pagination** | `api/src/backend/api/pagination.py` | `LimitedJsonApiPageNumberPagination` |
| **Permissions** | `api/src/backend/api/decorators.py` | `HasPermissions`, `@check_permissions` |
| **RBAC** | `api/src/backend/api/rbac/permissions.py` | `Permissions` enum, `get_role()`, `get_providers()` |
| **Settings** | `api/src/backend/config/settings.py` | `REST_FRAMEWORK` config |

## ViewSet Hierarchy

```
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

```
BaseModelSerializerV1 (JSON:API defaults, read_only_fields)
    │
    ├── RLSSerializer (auto-injects tenant_id from request)
    │       └── Most model serializers inherit this
    │
    └── BaseWriteSerializer (rejects unknown fields)
            └── Create/Update serializers

+ Mixins:
  - IncludedResourcesValidationMixin (validates ?include= param)
  - JSONAPIRelatedLinksSerializerMixin (adds related links)
```

## Filter Hierarchy

```
FilterSet (django-filter)
    │
    ├── CommonFindingFilters (mixin for date ranges, delta, status)
    │
    ├── BaseProviderFilter (provider_type, provider_uid, provider_alias)
    │       │
    │       └── BaseScanProviderFilter (+ scan_id, scan filters)
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
class ProviderFilter(BaseProviderFilter):
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
class ProviderCreateSerializer(BaseWriteSerializer, RLSSerializer):
    class Meta:
        model = Provider
        fields = ["provider", "uid", "alias"]
```

### ViewSet Action Pattern

```python
@action(detail=True, methods=["post"], url_path="scan")
def trigger_scan(self, request, pk=None):
    provider = self.get_object()
    task = perform_scan_task.delay(...)
    return Response(status=status.HTTP_202_ACCEPTED)
```

## REST_FRAMEWORK Settings

Located in `api/src/backend/config/settings.py`:

```python
REST_FRAMEWORK = {
    "PAGE_SIZE": 10,
    "DEFAULT_PAGINATION_CLASS": "api.pagination.LimitedJsonApiPageNumberPagination",
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework_json_api.parsers.JSONParser",
        "rest_framework.parsers.JSONParser",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ],
    "EXCEPTION_HANDLER": "rest_framework_json_api.exceptions.exception_handler",
    # ... more settings
}
```

## JSON:API Resource Names

Find all `JSONAPIMeta` declarations:
```bash
rg "resource_name" api/src/backend/api/models.py
```

Convention: kebab-case, plural (e.g., `provider-groups`, `mute-rules`)
