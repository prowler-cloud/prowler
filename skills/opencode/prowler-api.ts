
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-api
description: Django REST Framework patterns for Prowler API development. Covers models, serializers, views, filters, and Celery tasks with Row-Level Security (RLS).
license: Apache 2.0
---

## When to use this skill

Use this skill when working on the Prowler API (Django/DRF backend) for:
- Creating new models, serializers, views, or filters
- Understanding RLS (Row-Level Security) patterns
- Implementing Celery tasks
- Writing API tests

## Critical Rules

### Models
- ALWAYS: UUIDv4 primary keys
- ALWAYS: \`inserted_at\` / \`updated_at\` timestamps
- ALWAYS: \`JSONAPIMeta\` class for resource naming
- ALWAYS: Inherit from \`RowLevelSecurityProtectedModel\` for tenant data
- NEVER: Auto-increment integer PKs

### Serializers
- Read: \`<Model>Serializer\`
- Create: \`<Model>CreateSerializer\` (extends BaseWriteSerializer)
- Update: \`<Model>UpdateSerializer\` (extends BaseWriteSerializer)
- Include: \`<Model>IncludeSerializer\` (minimal fields)

### Views
- ALWAYS: Inherit from \`BaseRLSViewSet\`
- ALWAYS: Define \`filterset_class\`
- ALWAYS: Use \`@extend_schema\` for OpenAPI docs
- NEVER: Raw SQL queries (use ORM or \`rls_transaction\`)
- NEVER: Business logic in views (use tasks/services)

### RLS Pattern
\`\`\`python
from api.rls import rls_transaction

with rls_transaction(tenant_id):
    resources = Resource.objects.filter(provider=provider)
\`\`\`

### Celery Tasks
\`\`\`python
@shared_task(name="task-name", queue="scans", bind=True, base=RLSTask)
def process_task(self, tenant_id: str, entity_id: str):
    with rls_transaction(tenant_id):
        # task logic
\`\`\`

## JSON:API Format

Request/Response: \`application/vnd.api+json\`

\`\`\`json
{
  "data": {
    "type": "resources",
    "id": "uuid",
    "attributes": { "name": "value" },
    "relationships": {
      "provider": { "data": { "type": "providers", "id": "uuid" } }
    }
  }
}
\`\`\`

## Commands

\`\`\`bash
# Development
cd api && poetry run python src/backend/manage.py runserver
cd api && poetry run celery -A config.celery worker -l INFO

# Database
cd api && poetry run python src/backend/manage.py makemigrations
cd api && poetry run python src/backend/manage.py migrate

# Testing
cd api && poetry run pytest -x --tb=short
cd api && poetry run pytest -k "test_provider"
cd api && poetry run make lint
\`\`\`

## Keywords
prowler api, django, drf, rest framework, json:api, rls, celery, serializers, viewsets
`;

export default tool({
  description: SKILL,
  args: {
    operation: tool.schema.string().describe("Operation type: model, serializer, view, filter, task, test"),
    entity: tool.schema.string().describe("Entity/model name (e.g., Provider, Finding, Resource)"),
  },
  async execute(args) {
    return `
Prowler API Pattern for: ${args.operation} - ${args.entity}

Based on the operation "${args.operation}" for "${args.entity}", follow these patterns:

Model Location: api/src/backend/api/models.py
Serializer Location: api/src/backend/api/v1/serializers.py
View Location: api/src/backend/api/v1/views.py
Filter Location: api/src/backend/api/filters.py
Task Location: api/src/backend/tasks/tasks.py
Test Location: api/src/backend/api/tests/

Key imports:
- from api.models import ${args.entity}
- from api.rls import rls_transaction
- from api.base_views import BaseRLSViewSet

Remember:
- All tenant data MUST use RLS
- Use JSON:API format for all requests/responses
- Separate serializers for read/create/update operations
    `.trim()
  },
})
