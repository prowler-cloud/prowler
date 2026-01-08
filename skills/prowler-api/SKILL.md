---
name: prowler-api
description: >
  Prowler API-specific patterns. For generic DRF, see: django-drf, pytest.
  Trigger: When working on api/ directory - models, serializers, views, filters, tasks.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## Related Generic Skills

- `django-drf` - ViewSets, Serializers, Filters
- `pytest` - Fixtures, mocking, markers

## Prowler-Specific: Row-Level Security (RLS)

### Critical Pattern

```python
from api.db_utils import rls_transaction

# ALWAYS use rls_transaction for tenant-scoped queries
with rls_transaction(tenant_id):
    resources = Resource.objects.filter(provider=provider)

# NEVER query across tenants
```

### Models

```python
from api.models import RowLevelSecurityProtectedModel

class Resource(RowLevelSecurityProtectedModel):
    id = models.UUIDField(primary_key=True, default=uuid4)
    inserted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class JSONAPIMeta:
        resource_name = "resources"
```

### Views

```python
from api.base_views import BaseRLSViewSet

class ResourceViewSet(BaseRLSViewSet):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    filterset_class = ResourceFilter
```

### Celery Tasks

```python
from celery import shared_task
from config.celery import RLSTask

@shared_task(name="process-resource", queue="scans", bind=True, base=RLSTask)
def process_resource_task(self, tenant_id: str, resource_id: str):
    with rls_transaction(tenant_id):
        # task logic
```

## Serializer Naming

- Read: `ResourceSerializer`
- Create: `ResourceCreateSerializer`
- Update: `ResourceUpdateSerializer`
- Include: `ResourceIncludeSerializer`

## JSON:API Format

```json
{
  "data": {
    "type": "resources",
    "id": "uuid",
    "attributes": { "name": "value" },
    "relationships": { "provider": { "data": { "type": "providers", "id": "uuid" } } }
  }
}
```

Content-Type: `application/vnd.api+json`

## Commands

```bash
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run pytest -x --tb=short
```

## Keywords
prowler api, django, drf, rls, json:api, celery
