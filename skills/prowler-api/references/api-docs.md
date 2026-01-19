# API Documentation

## Local Documentation

For API-related patterns, see:

- `api/src/backend/api/models.py` - Models, Providers, UID validation
- `api/src/backend/api/v1/views.py` - ViewSets, RBAC patterns
- `api/src/backend/api/v1/serializers.py` - Serializers
- `api/src/backend/api/rbac/permissions.py` - RBAC functions
- `api/src/backend/tasks/tasks.py` - Celery tasks
- `api/src/backend/api/db_utils.py` - rls_transaction

## Contents

The documentation covers:
- Row-Level Security (RLS) implementation
- RBAC permission system
- Provider validation patterns
- Celery task orchestration
- JSON:API serialization format
