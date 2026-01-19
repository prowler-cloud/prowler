---
name: django-drf
description: >
  Django REST Framework patterns.
  Trigger: When implementing generic DRF APIs (ViewSets, serializers, routers, permissions, filtersets). For Prowler API specifics (RLS/RBAC/Providers), also use prowler-api.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1.0"
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
- ALWAYS validate unknown fields in write serializers
- ALWAYS use `select_related`/`prefetch_related` in `get_queryset()` to avoid N+1
- ALWAYS handle `swagger_fake_view` in `get_queryset()` for schema generation
- NEVER put business logic in serializers - use services/utils
- NEVER use auto-increment PKs - use UUIDv4 or UUIDv7
- NEVER use trailing slashes in URLs (`trailing_slash=False`)

---

## Implementation Checklist

When implementing a new endpoint, review these patterns in order:

| # | Pattern | Reference | Key Points |
|---|---------|-----------|------------|
| 1 | **Models** | `api/models.py` | UUID PK, `inserted_at`/`updated_at`, `JSONAPIMeta.resource_name` |
| 2 | **ViewSets** | `api/base_views.py`, `api/v1/views.py` | Inherit `BaseRLSViewSet`, `get_queryset()` with N+1 prevention |
| 3 | **Serializers** | `api/v1/serializers.py` | Separate Read/Create/Update/Include, inherit `BaseWriteSerializer` |
| 4 | **Filters** | `api/filters.py` | Use `filterset_class`, inherit `BaseProviderFilter` if applicable |
| 5 | **Permissions** | `api/decorators.py` | `required_permissions`, `set_required_permissions()` |
| 6 | **Pagination** | `api/pagination.py` | Custom pagination class if needed |
| 7 | **URL Routing** | `api/v1/urls.py` | `trailing_slash=False`, kebab-case paths |
| 8 | **OpenAPI Schema** | `api/v1/views.py` | `@extend_schema_view` decorators |
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

### Which Filter Base?
```
Direct FK to Provider  → BaseProviderFilter
FK via Scan           → BaseScanProviderFilter
No provider relation  → FilterSet
```

### Which Base ViewSet?
```
RLS-protected model  → BaseRLSViewSet
Tenant operations    → BaseTenantViewset
User operations      → BaseUserViewset
```

### Resource Name Format?
```
Single word model     → plural lowercase           (Provider → providers)
Multi-word model      → plural lowercase kebab     (ProviderGroup → provider-groups)
Through/join model    → parent-child pattern       (UserRoleRelationship → user-roles)
Aggregation/overview  → descriptive kebab plural   (ComplianceOverview → compliance-overviews)
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

- **File Locations**: See [references/file-locations.md](references/file-locations.md)
- **JSON:API Conventions**: See [references/json-api-conventions.md](references/json-api-conventions.md)
- **DRF Docs**: https://www.django-rest-framework.org/
- **DRF JSON:API**: https://django-rest-framework-json-api.readthedocs.io/
- **django-filter**: https://django-filter.readthedocs.io/
