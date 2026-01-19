# Django-DRF File Locations

## Core API Files

| Pattern | File Path | Key Classes |
|---------|-----------|-------------|
| **Models** | `api/src/backend/api/models.py` | `Provider`, `Scan`, `Finding`, `Resource`, `StateChoices` |
| **Base ViewSets** | `api/src/backend/api/base_views.py` | `BaseViewSet`, `BaseRLSViewSet`, `BaseTenantViewset` |
| **ViewSets** | `api/src/backend/api/v1/views.py` | `ProviderViewSet`, `ScanViewSet`, `ResourceViewSet` |
| **Serializers** | `api/src/backend/api/v1/serializers.py` | `BaseModelSerializerV1`, `BaseWriteSerializer`, `RLSSerializer` |
| **Filters** | `api/src/backend/api/filters.py` | `BaseProviderFilter`, `BaseScanProviderFilter`, `ProviderFilter` |
| **URL Routing** | `api/src/backend/api/v1/urls.py` | Router setup, nested routes |
| **Pagination** | `api/src/backend/api/pagination.py` | `ComplianceOverviewPagination` |
| **Permissions** | `api/src/backend/api/decorators.py` | `HasPermissions`, RBAC decorators |
| **Settings** | `api/src/backend/config/django/base.py` | `REST_FRAMEWORK` config |

## Testing Files

| Pattern | File Path | Key Classes |
|---------|-----------|-------------|
| **ViewSet Tests** | `api/src/backend/api/tests/test_views.py` | Test patterns, fixtures |
| **Conftest** | `api/src/backend/conftest.py` | Shared fixtures |

## Key Line References

Use these as starting points when implementing:

### Base Classes (api/src/backend/api/base_views.py)
- `BaseViewSet` - Line ~20
- `BaseRLSViewSet` - Line ~65
- `BaseTenantViewset` - Line ~105
- `BaseUserViewset` - Line ~174

### Filters (api/src/backend/api/filters.py)
- `UUIDInFilter`, `CharInFilter` - Lines ~15-30
- `BaseProviderFilter` - Line ~98
- `BaseScanProviderFilter` - Line ~122
- `CommonFindingFilters` - Line ~146
- `ProviderFilter` - Line ~293
- `ResourceFilter` - Line ~455

### Serializers (api/src/backend/api/v1/serializers.py)
- `BaseModelSerializerV1` - Line ~50
- `BaseWriteSerializer` - Line ~65
- `RLSSerializer` - Line ~80
- `ProviderSerializer` - Search for `class ProviderSerializer`
- `ProviderCreateSerializer` - Search for `class ProviderCreateSerializer`

## JSON:API Resource Names

Find all `JSONAPIMeta` declarations:
```bash
rg "resource_name" api/src/backend/api/models.py
```

## REST_FRAMEWORK Settings

See `api/src/backend/config/django/base.py` line ~85 for full configuration including:
- `DEFAULT_PAGINATION_CLASS`
- `DEFAULT_FILTER_BACKENDS`
- `DEFAULT_PARSER_CLASSES`
- `EXCEPTION_HANDLER`
