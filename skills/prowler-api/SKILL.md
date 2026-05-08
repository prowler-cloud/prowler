---
name: prowler-api
description: "Trigger: When working in `api/` on Prowler-specific models, serializers, viewsets, filters, Celery tasks, provider lifecycle, RBAC, or tenant isolation. Applies the repository’s RLS-first API contract."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
  scope: [root, api]
  auto_invoke: "Creating/modifying models, views, serializers"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill for Prowler API behavior that depends on tenant isolation, RBAC visibility, provider orchestration, or Celery execution semantics. Pair it with `django-drf` for generic DRF patterns and `jsonapi` for response-shape compliance.

## Hard Rules

- Always preserve RLS boundaries; queries outside request-scoped viewsets must run inside `rls_transaction(tenant_id)`.
- Always check permissions through the repo’s RBAC helpers before assuming provider visibility.
- Always model tenant-scoped M2M relations with explicit through models carrying `tenant_id`.
- Always keep Celery tenant setup and provider-deletion handling in the established decorator/base-task flow.
- Never bypass RLS with raw SQL, unmanaged cursors, or admin connections unless the design explicitly requires cross-tenant access.
- Never invent generic DRF patterns here when `django-drf` already owns them.

## Decision Gates

| Question | Action |
|---|---|
| Is the behavior tenant-scoped data access? | Use RLS-safe models, serializers, and `rls_transaction()` where request context is absent. |
| Is the endpoint mostly generic DRF plumbing? | Load `django-drf` alongside this skill. |
| Is the concern response/media-type compliance? | Load `jsonapi` alongside this skill. |
| Is this async provider or scan orchestration? | Use Celery patterns with tenant-aware task setup. |
| Does the query need admin or cross-tenant access? | Escalate the reason explicitly and use the admin path sparingly. |

## Execution Steps

1. Classify the change: RLS model, RBAC/viewset flow, provider lifecycle, serializer boundary, or Celery workflow.
2. Identify where tenant context comes from and where it could be lost.
3. Choose the correct base abstractions for models, serializers, viewsets, and tasks.
4. Validate relationship modeling, provider visibility, and async handoff against existing Prowler patterns.
5. Cross-check the implementation with `django-drf` and `jsonapi` when endpoint behavior is involved.
6. Return only the repo-specific constraints that materially affect the change.

## Output Contract

- State the Prowler-specific API constraint that governs the task: RLS, RBAC, provider lifecycle, or Celery tenant handling.
- Name any companion skills required, especially `django-drf` and `jsonapi`.
- Call out the exact files or modules to inspect next.
- Mention any high-risk boundary where tenant isolation or provider visibility could break.

## References

- [Repository agent rules](../../AGENTS.md)
- [API component guidance](../../api/AGENTS.md)
- [API file locations](references/file-locations.md)
- [API modeling decisions](references/modeling-decisions.md)
- [API configuration](references/configuration.md)
- [Production settings notes](references/production-settings.md)
- [Celery patterns asset](assets/celery_patterns.py)
- [Security patterns asset](assets/security_patterns.py)
