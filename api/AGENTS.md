# Prowler API - AI Agent Ruleset

> **Skills Reference**: For detailed patterns, use these skills:
> - [`prowler-api`](../skills/prowler-api/SKILL.md) - Models, Serializers, Views, RLS patterns
> - [`prowler-test-api`](../skills/prowler-test-api/SKILL.md) - Testing patterns (pytest-django)
> - [`django-drf`](../skills/django-drf/SKILL.md) - Generic DRF patterns
> - [`jsonapi`](../skills/jsonapi/SKILL.md) - Strict JSON:API v1.1 spec compliance
> - [`pytest`](../skills/pytest/SKILL.md) - Generic pytest patterns

### Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action | Skill |
|--------|-------|
| Add changelog entry for a PR or feature | `prowler-changelog` |
| Adding DRF pagination or permissions | `django-drf` |
| Committing changes | `prowler-commit` |
| Create PR that requires changelog entry | `prowler-changelog` |
| Creating API endpoints | `jsonapi` |
| Creating ViewSets, serializers, or filters in api/ | `django-drf` |
| Creating a git commit | `prowler-commit` |
| Creating/modifying models, views, serializers | `prowler-api` |
| Implementing JSON:API endpoints | `django-drf` |
| Modifying API responses | `jsonapi` |
| Review changelog format and conventions | `prowler-changelog` |
| Reviewing JSON:API compliance | `jsonapi` |
| Testing RLS tenant isolation | `prowler-test-api` |
| Update CHANGELOG.md in any component | `prowler-changelog` |
| Writing Prowler API tests | `prowler-test-api` |
| Writing Python tests with pytest | `pytest` |

---

## CRITICAL RULES - NON-NEGOTIABLE

### Models
- ALWAYS: UUIDv4 PKs, `inserted_at`/`updated_at` timestamps, `JSONAPIMeta` class
- ALWAYS: Inherit from `RowLevelSecurityProtectedModel` for tenant-scoped data
- NEVER: Auto-increment integer PKs, models without tenant isolation

### Serializers
- ALWAYS: Separate serializers for Create/Update operations
- ALWAYS: Inherit from `RLSSerializer` for tenant-scoped models
- NEVER: Write logic in serializers (use services/utils)

### Views
- ALWAYS: Inherit from `BaseRLSViewSet` for tenant-scoped resources
- ALWAYS: Define `filterset_class`, use `@extend_schema` for OpenAPI
- NEVER: Raw SQL queries, business logic in views

### Row-Level Security (RLS)
- ALWAYS: Use `rls_transaction(tenant_id)` context manager
- NEVER: Query across tenants, trust client-provided tenant_id

### Celery Tasks
- ALWAYS: `@shared_task` with `name`, `queue`, `RLSTask` base class
- NEVER: Long-running ops in views, request context in tasks

---

## DECISION TREES

### Serializer Selection
```
Read → <Model>Serializer
Create → <Model>CreateSerializer
Update → <Model>UpdateSerializer
Nested read → <Model>IncludeSerializer
```

### Task vs View
```
< 100ms → View
> 100ms or external API → Celery task
Needs retry → Celery task
```

---

## TECH STACK

Django 5.1.x | DRF 3.15.x | djangorestframework-jsonapi 7.x | Celery 5.4.x | PostgreSQL 16 | pytest 8.x

---

## PROJECT STRUCTURE

```
api/src/backend/
├── api/                    # Main Django app
│   ├── v1/                # API version 1 (views, serializers, urls)
│   ├── models.py          # Django models
│   ├── filters.py         # FilterSet classes
│   ├── base_views.py      # Base ViewSet classes
│   ├── rls.py             # Row-Level Security
│   └── tests/             # Unit tests
├── config/                # Django configuration
└── tasks/                 # Celery tasks
```

---

## COMMANDS

```bash
# Development
poetry run python src/backend/manage.py runserver
poetry run celery -A config.celery worker -l INFO

# Database
poetry run python src/backend/manage.py makemigrations
poetry run python src/backend/manage.py migrate

# Testing & Linting
poetry run pytest -x --tb=short
poetry run make lint
```

---

## QA CHECKLIST

- [ ] `poetry run pytest` passes
- [ ] `poetry run make lint` passes
- [ ] Migrations created if models changed
- [ ] New endpoints have `@extend_schema` decorators
- [ ] RLS properly applied for tenant data
- [ ] Tests cover success and error cases

---

## NAMING CONVENTIONS

| Entity | Pattern | Example |
|--------|---------|---------|
| Serializer (read) | `<Model>Serializer` | `ProviderSerializer` |
| Serializer (create) | `<Model>CreateSerializer` | `ProviderCreateSerializer` |
| Serializer (update) | `<Model>UpdateSerializer` | `ProviderUpdateSerializer` |
| Filter | `<Model>Filter` | `ProviderFilter` |
| ViewSet | `<Model>ViewSet` | `ProviderViewSet` |
| Task | `<action>_<entity>_task` | `sync_provider_resources_task` |

---

## API CONVENTIONS (JSON:API)

```json
{
  "data": {
    "type": "providers",
    "id": "uuid",
    "attributes": { "name": "value" },
    "relationships": { "tenant": { "data": { "type": "tenants", "id": "uuid" } } }
  }
}
```

- Content-Type: `application/vnd.api+json`
- Pagination: `?page[number]=1&page[size]=20`
- Filtering: `?filter[field]=value`, `?filter[field__in]=val1,val2`
- Sorting: `?sort=field`, `?sort=-field`
- Including: `?include=provider,findings`
