---
name: django-drf
description: >
  Django REST Framework patterns.
  Trigger: When implementing generic DRF APIs (ViewSets, serializers, routers, permissions, filtersets). For Prowler API specifics (RLS/JSON:API), also use prowler-api.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, api]
  auto_invoke: "Generic DRF patterns"
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

## 1. Model Patterns

### UUID Primary Keys with Timestamps

```python
from uuid import uuid4
from django.db import models

class Provider(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        db_table = "providers"

    class JSONAPIMeta:
        resource_name = "providers"
```

### Choices with TextChoices

```python
class StateChoices(models.TextChoices):
    AVAILABLE = "available", _("Available")
    SCHEDULED = "scheduled", _("Scheduled")
    EXECUTING = "executing", _("Executing")
    COMPLETED = "completed", _("Completed")
    FAILED = "failed", _("Failed")
```

### Custom Manager for Soft Delete

```python
class ActiveProviderManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(is_deleted=False)

class Provider(models.Model):
    objects = ActiveProviderManager()      # Default excludes deleted
    all_objects = models.Manager()         # Includes deleted
```

---

## 2. ViewSet Patterns

### Base ViewSet with Filter Backends

```python
from rest_framework import permissions
from rest_framework.filters import SearchFilter
from rest_framework_json_api import filters
from rest_framework_json_api.views import ModelViewSet

class BaseViewSet(ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        filters.QueryParameterValidationFilter,
        filters.OrderingFilter,
        DjangoFilterBackend,
        SearchFilter,
    ]
    ordering_fields = "__all__"
    ordering = ["id"]
```

### Serializer Selection by Action

```python
class ProviderViewSet(BaseViewSet):
    queryset = Provider.objects.all()
    serializer_class = ProviderSerializer
    filterset_class = ProviderFilter
    http_method_names = ["get", "post", "patch", "delete"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "updated_at", "alias"]

    def get_queryset(self):
        # Handle schema generation (drf-spectacular)
        if getattr(self, "swagger_fake_view", False):
            return Provider.objects.none()

        # Use select_related/prefetch_related to avoid N+1 queries
        return Provider.objects.filter(
            tenant_id=self.request.tenant_id
        ).select_related("secret").prefetch_related("provider_groups")

    def get_serializer_class(self):
        if self.action == "create":
            return ProviderCreateSerializer
        elif self.action == "partial_update":
            return ProviderUpdateSerializer
        return ProviderSerializer
```

### Custom Actions

```python
from rest_framework.decorators import action
from rest_framework.response import Response

class UserViewSet(BaseViewSet):
    @action(detail=False, methods=["get"], url_name="me")
    def me(self, request):
        serializer = UserSerializer(request.user, context=self.get_serializer_context())
        return Response(data=serializer.data, status=status.HTTP_200_OK)
```

### Dynamic Permission Setting

```python
class ProviderViewSet(BaseViewSet):
    required_permissions = [Permissions.MANAGE_PROVIDERS]

    def set_required_permissions(self):
        if self.request.method in SAFE_METHODS:
            self.required_permissions = []
        else:
            self.required_permissions = [Permissions.MANAGE_PROVIDERS]
```

---

## 3. Serializer Patterns

### Base Model Serializer with Version Meta

```python
from rest_framework_json_api import serializers

class BaseModelSerializerV1(serializers.ModelSerializer):
    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}
```

### Write Serializer with Unknown Field Validation

```python
class BaseWriteSerializer(BaseModelSerializerV1):
    def validate(self, data):
        if hasattr(self, "initial_data"):
            initial_data = set(self.initial_data.keys()) - {"id", "type"}
            unknown_keys = initial_data - set(self.fields.keys())
            if unknown_keys:
                raise ValidationError(f"Invalid fields: {unknown_keys}")
        return data
```

### Read Serializer (List/Retrieve)

```python
class ProviderSerializer(BaseModelSerializerV1):
    connection = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Provider
        fields = ["id", "inserted_at", "updated_at", "provider", "uid", "alias", "connection"]

    included_serializers = {
        "provider_groups": "api.v1.serializers.ProviderGroupIncludedSerializer",
    }

    def get_connection(self, obj):
        return {"connected": obj.connected, "last_checked_at": obj.connection_last_checked_at}
```

### Create Serializer

```python
class ProviderCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Provider
        fields = ["alias", "provider", "uid"]
        extra_kwargs = {
            "alias": {"help_text": "Human readable name"},
            "provider": {"help_text": "Type of provider"},
            "uid": {"help_text": "Unique identifier from provider"},
        }
```

### Update Serializer (Restricted Fields)

```python
class ProviderUpdateSerializer(BaseWriteSerializer):
    class Meta:
        model = Provider
        fields = ["alias"]  # Only allow updating alias
        extra_kwargs = {
            "alias": {"help_text": "Human readable name"},
        }
```

### Include Serializer (Nested/Related)

```python
class ProviderIncludeSerializer(BaseModelSerializerV1):
    """Minimal fields for ?include=provider"""

    class Meta:
        model = Provider
        fields = ["id", "inserted_at", "provider", "uid", "alias"]
```

### Relationship Serializers (Many-to-Many)

```python
class UserRoleRelationshipSerializer(RLSSerializer, BaseWriteSerializer):
    roles = serializers.ListField(
        child=RoleResourceIdentifierSerializer(),
        help_text="List of role identifiers",
    )

    def create(self, validated_data):
        role_ids = [item["id"] for item in validated_data["roles"]]
        roles = Role.objects.filter(id__in=role_ids)
        tenant_id = self.context.get("tenant_id")

        new_relationships = [
            UserRoleRelationship(user=self.context.get("user"), role=r, tenant_id=tenant_id)
            for r in roles
        ]
        UserRoleRelationship.objects.bulk_create(new_relationships)
        return self.context.get("user")
```

---

## 4. Filter Patterns

### Abstract Base Filter (Reusable)

```python
from django_filters.rest_framework import (
    BaseInFilter, CharFilter, ChoiceFilter, DateFilter, FilterSet, UUIDFilter
)

class UUIDInFilter(BaseInFilter, UUIDFilter):
    pass

class CharInFilter(BaseInFilter, CharFilter):
    pass

class ChoiceInFilter(BaseInFilter, ChoiceFilter):
    pass

class BaseProviderFilter(FilterSet):
    """Abstract filter for models with FK to Provider."""
    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(field_name="provider__provider", choices=Provider.ProviderChoices.choices)

    class Meta:
        abstract = True
```

### Concrete Filter with Date and Choices

```python
class ProviderFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    connected = BooleanFilter()
    provider = ChoiceFilter(choices=Provider.ProviderChoices.choices)
    provider__in = ChoiceInFilter(field_name="provider", choices=Provider.ProviderChoices.choices, lookup_expr="in")

    class Meta:
        model = Provider
        fields = {
            "provider": ["exact", "in"],
            "id": ["exact", "in"],
            "uid": ["exact", "icontains", "in"],
            "alias": ["exact", "icontains", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }
```

### Custom Filter Methods

```python
class ResourceFilter(FilterSet):
    tag = CharFilter(method="filter_tag")
    groups = CharFilter(method="filter_groups")
    groups__in = CharInFilter(field_name="groups", lookup_expr="overlap")

    def filter_groups(self, queryset, name, value):
        return queryset.filter(groups__contains=[value])

    def filter_tag(self, queryset, name, value):
        return queryset.filter(tags__text_search=value)
```

### Validation in filter_queryset

```python
class FindingFilter(FilterSet):
    def filter_queryset(self, queryset):
        # Require at least one date filter
        if not (self.data.get("scan") or self.data.get("inserted_at__gte")):
            raise ValidationError([{
                "detail": "At least one date filter required",
                "status": 400,
                "source": {"pointer": "/data/attributes/inserted_at"},
                "code": "required",
            }])
        return super().filter_queryset(queryset)
```

---

## 5. Custom Permissions

```python
from rest_framework.permissions import BasePermission

class HasPermissions(BasePermission):
    def has_permission(self, request, view):
        required = getattr(view, "required_permissions", [])
        if not required:
            return True
        user_role = get_role(request.user)
        return all(getattr(user_role, perm.value, False) for perm in required)
```

---

## 6. Pagination

```python
from drf_spectacular_jsonapi.schemas.pagination import JsonApiPageNumberPagination

class ComplianceOverviewPagination(JsonApiPageNumberPagination):
    page_size = 50
    max_page_size = 100

# settings.py - Use drf_spectacular_jsonapi for JSON:API compliance
REST_FRAMEWORK = {
    "PAGE_SIZE": 10,
    "DEFAULT_PAGINATION_CLASS": "drf_spectacular_jsonapi.schemas.pagination.JsonApiPageNumberPagination",
}
```

### Custom Pagination per ViewSet

```python
class ComplianceOverviewViewSet(BaseRLSViewSet):
    pagination_class = ComplianceOverviewPagination
```

---

## 7. URL Routing

```python
from rest_framework_nested import routers

# No trailing slashes
router = routers.DefaultRouter(trailing_slash=False)
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(r"provider-groups", ProviderGroupViewSet, basename="providergroup")

# Nested routes for sub-resources
tenants_router = routers.NestedSimpleRouter(router, r"tenants", lookup="tenant")
tenants_router.register(r"memberships", TenantMembersViewSet, basename="tenant-membership")

urlpatterns = [
    path("api/v1/", include(router.urls)),
    path("api/v1/", include(tenants_router.urls)),
]
```

### Relationship Endpoints (Manual Registration)

```python
# For JSON:API relationship endpoints
path(
    "users/<uuid:pk>/relationships/roles",
    UserRoleRelationshipView.as_view({
        "post": "create",
        "patch": "partial_update",
        "delete": "destroy"
    }),
    name="user-roles-relationship",
),
```

---

## 8. Testing (pytest-django)

```python
import pytest
from rest_framework import status
from rest_framework.test import APIClient

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def authenticated_client(api_client, user, tenant):
    api_client.force_authenticate(user=user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {get_token(user, tenant)}")
    return api_client

@pytest.mark.django_db
class TestProviderViewSet:
    def test_list_providers(self, authenticated_client):
        response = authenticated_client.get(
            "/api/v1/providers/",
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert "data" in response.json()

    def test_create_provider(self, authenticated_client):
        data = {
            "data": {
                "type": "providers",
                "attributes": {"provider": "aws", "uid": "123456789012"},
            }
        }
        response = authenticated_client.post(
            "/api/v1/providers/",
            data=data,
            format="json",
            content_type="application/vnd.api+json",
        )
        assert response.status_code == status.HTTP_201_CREATED
```

---

## 9. OpenAPI Schema Decorators

```python
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiResponse

@extend_schema_view(
    list=extend_schema(
        tags=["Provider"],
        summary="List all providers",
        description="Retrieve all providers with filtering options.",
    ),
    create=extend_schema(
        tags=["Provider"],
        summary="Create a provider",
        request=ProviderCreateSerializer,
        responses={201: ProviderSerializer},
    ),
)
class ProviderViewSet(BaseViewSet):
    pass
```

---

## 10. JSON:API Conventions

### Content Type

```
Content-Type: application/vnd.api+json
Accept: application/vnd.api+json
```

### Resource Naming (JSONAPIMeta)

**Rules:**
- Use **lowercase kebab-case** (hyphens, not underscores)
- Use **plural nouns** for collections
- Resource name in `JSONAPIMeta` MUST match URL path segment

```python
# Model
class ProviderGroup(models.Model):
    class JSONAPIMeta:
        resource_name = "provider-groups"  # kebab-case, plural

# URL registration
router.register(r"provider-groups", ProviderGroupViewSet, basename="providergroup")
```

| Model | resource_name | URL Path |
|-------|---------------|----------|
| `Provider` | `providers` | `/api/v1/providers` |
| `ProviderGroup` | `provider-groups` | `/api/v1/provider-groups` |
| `ProviderSecret` | `provider-secrets` | `/api/v1/providers/secrets` |
| `ComplianceOverview` | `compliance-overviews` | `/api/v1/compliance-overviews` |
| `AttackPathsScan` | `attack-paths-scans` | `/api/v1/attack-paths-scans` |
| `TenantAPIKey` | `api-keys` | `/api/v1/api-keys` |
| `MuteRule` | `mute-rules` | `/api/v1/mute-rules` |

### Relationship Endpoints

Pattern: `/{resource}/{id}/relationships/{relation}`

```python
# URL
path(
    "users/<uuid:pk>/relationships/roles",
    UserRoleRelationshipView.as_view({...}),
    name="user-roles-relationship",
)

# resource_name for through models
class UserRoleRelationship(models.Model):
    class JSONAPIMeta:
        resource_name = "user-roles"

class RoleProviderGroupRelationship(models.Model):
    class JSONAPIMeta:
        resource_name = "role-provider_groups"
```

### Request/Response Format

```json
// Request (POST/PATCH)
{
  "data": {
    "type": "providers",
    "attributes": {
      "provider": "aws",
      "uid": "123456789012",
      "alias": "Production"
    }
  }
}

// Response
{
  "data": {
    "type": "providers",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "attributes": {
      "provider": "aws",
      "uid": "123456789012",
      "alias": "Production",
      "inserted_at": "2024-01-15T10:30:00Z"
    },
    "relationships": {
      "provider_groups": {
        "data": [{"type": "provider-groups", "id": "..."}]
      }
    },
    "links": {
      "self": "/api/v1/providers/550e8400-e29b-41d4-a716-446655440000"
    }
  },
  "meta": {
    "version": "v1"
  }
}
```

### Query Parameters

| Feature | Format | Example |
|---------|--------|---------|
| **Pagination** | `page[number]`, `page[size]` | `?page[number]=2&page[size]=20` |
| **Filtering** | `filter[field]`, `filter[field__lookup]` | `?filter[status]=FAIL&filter[inserted_at__gte]=2024-01-01` |
| **Sorting** | `sort` (prefix `-` for desc) | `?sort=-inserted_at,name` |
| **Sparse fields** | `fields[type]` | `?fields[providers]=id,alias,uid` |
| **Includes** | `include` | `?include=provider,scan` |
| **Search** | `filter[search]` | `?filter[search]=production` |

### Filter Naming Conventions

| Lookup | Django Filter | JSON:API Query |
|--------|--------------|----------------|
| Exact | `field` | `filter[field]=value` |
| Contains | `field__icontains` | `filter[field__icontains]=val` |
| In list | `field__in` | `filter[field__in]=a,b,c` |
| Greater/equal | `field__gte` | `filter[field__gte]=2024-01-01` |
| Less/equal | `field__lte` | `filter[field__lte]=2024-12-31` |
| Related field | `relation__field` | `filter[provider_id]=uuid` |

### Error Response Format

```json
{
  "errors": [
    {
      "detail": "At least one date filter is required",
      "status": "400",
      "source": {"pointer": "/data/attributes/inserted_at"},
      "code": "required"
    }
  ]
}
```

### Included Serializers (Sideloading)

```python
class ScanSerializer(BaseModelSerializerV1):
    class Meta:
        model = Scan
        fields = ["id", "state", "provider", "task"]

    included_serializers = {
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
        "task": "api.v1.serializers.TaskSerializer",
    }
```

Request: `GET /api/v1/scans/123?include=provider,task`

Response includes `"included": [...]` with related resources.

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

### Resource Name Format?
```
Single word model     → plural lowercase           (Provider → providers)
Multi-word model      → plural lowercase kebab     (ProviderGroup → provider-groups)
Through/join model    → parent-child pattern       (UserRoleRelationship → user-roles)
Aggregation/overview  → descriptive kebab plural   (ComplianceOverview → compliance-overviews)
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

## Naming Conventions

### Python Classes

| Entity | Pattern | Example |
|--------|---------|---------|
| Serializer (read) | `<Model>Serializer` | `ProviderSerializer` |
| Serializer (create) | `<Model>CreateSerializer` | `ProviderCreateSerializer` |
| Serializer (update) | `<Model>UpdateSerializer` | `ProviderUpdateSerializer` |
| Serializer (include) | `<Model>IncludeSerializer` | `ProviderIncludeSerializer` |
| Filter | `<Model>Filter` | `ProviderFilter` |
| ViewSet | `<Model>ViewSet` | `ProviderViewSet` |
| Manager | `Active<Model>Manager` | `ActiveProviderManager` |

### JSON:API Resources

| Model Type | resource_name | URL Path |
|------------|---------------|----------|
| Simple | `providers` | `/providers` |
| Compound | `provider-groups` | `/provider-groups` |
| Nested | `provider-secrets` | `/providers/secrets` |
| Through table | `user-roles` | (relationship only) |
| Aggregation | `compliance-overviews` | `/compliance-overviews` |

### URL Endpoints

| Operation | Method | URL Pattern |
|-----------|--------|-------------|
| List | GET | `/{resources}` |
| Create | POST | `/{resources}` |
| Retrieve | GET | `/{resources}/{id}` |
| Update | PATCH | `/{resources}/{id}` |
| Delete | DELETE | `/{resources}/{id}` |
| Relationship | * | `/{resources}/{id}/relationships/{relation}` |
| Nested list | GET | `/{parent}/{parent_id}/{resources}` |

---

## REST_FRAMEWORK Settings (JSON:API)

```python
REST_FRAMEWORK = {
    # Schema
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular_jsonapi.schemas.openapi.JsonApiAutoSchema",

    # Authentication
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "api.authentication.CombinedJWTOrAPIKeyAuthentication",
    ),

    # Pagination
    "PAGE_SIZE": 10,
    "DEFAULT_PAGINATION_CLASS": "drf_spectacular_jsonapi.schemas.pagination.JsonApiPageNumberPagination",

    # Parsers (JSON:API format)
    "DEFAULT_PARSER_CLASSES": (
        "rest_framework_json_api.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
    ),

    # Renderers
    "DEFAULT_RENDERER_CLASSES": ("api.renderers.APIJSONRenderer",),

    # Metadata
    "DEFAULT_METADATA_CLASS": "rest_framework_json_api.metadata.JSONAPIMetadata",

    # Filters
    "DEFAULT_FILTER_BACKENDS": (
        "rest_framework_json_api.filters.QueryParameterValidationFilter",
        "rest_framework_json_api.filters.OrderingFilter",
        "rest_framework_json_api.django_filters.backends.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "SEARCH_PARAM": "filter[search]",

    # Testing
    "TEST_REQUEST_RENDERER_CLASSES": (
        "rest_framework_json_api.renderers.JSONRenderer",
    ),
    "TEST_REQUEST_DEFAULT_FORMAT": "vnd.api+json",

    # Exceptions
    "EXCEPTION_HANDLER": "api.exceptions.custom_exception_handler",
    "JSON_API_UNIFORM_EXCEPTIONS": True,
}
```

---

## Resources

- **DRF Docs**: https://www.django-rest-framework.org/
- **DRF JSON:API**: https://django-rest-framework-json-api.readthedocs.io/
- **django-filter**: https://django-filter.readthedocs.io/
- **drf-spectacular**: https://drf-spectacular.readthedocs.io/
- **drf-spectacular-jsonapi**: https://github.com/jokiefer/drf-spectacular-jsonapi
