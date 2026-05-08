---
name: django-drf
description: "Trigger: When implementing generic DRF APIs such as viewsets, serializers, routers, permissions, pagination, or filtersets, including JSON:API-capable endpoints. Applies the shared DRF execution patterns used in Prowler."
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.2.0"
  scope: [root, api]
  auto_invoke:
    - "Creating ViewSets, serializers, or filters in api/"
    - "Implementing JSON:API endpoints"
    - "Adding DRF pagination or permissions"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Activation Contract

Use this skill for generic DRF implementation structure: serializer layering, viewset composition, filtersets, routing, pagination, schema annotations, and query efficiency. Pair it with `jsonapi` for spec compliance and `prowler-api` when tenant isolation, RBAC, providers, or Celery-specific behavior enters the picture.

## Hard Rules

- Always separate serializer responsibilities by operation instead of one serializer doing everything.
- Always use `filterset_class` for meaningful filtering logic.
- Always validate unknown write fields through the repo’s write-serializer pattern.
- Always protect `get_queryset()` with `swagger_fake_view` handling and N+1 prevention.
- Always prefer UUID-based identifiers and kebab-case API paths.
- Never hide business logic in serializers when it belongs in services, utilities, or domain code.

## Decision Gates

| Question | Action |
|---|---|
| Is this a generic DRF endpoint concern? | Use this skill as the primary implementation guide. |
| Is the task about payload compliance rather than mechanics? | Load `jsonapi` too. |
| Is the endpoint Prowler-specific because of RLS, RBAC, or providers? | Load `prowler-api` too. |
| Do reads and writes have different responsibilities? | Split read, create, update, and include serializers. |
| Could the queryset explode into N+1 queries or schema-generation failures? | Fix `get_queryset()` with eager loading and `swagger_fake_view` handling. |

## Execution Steps

1. Identify the endpoint surface: model, serializer set, filterset, router path, permission rule, or schema annotation.
2. Choose the correct base classes for read, write, include, and viewset behavior.
3. Design `get_queryset()` for correctness first, then add eager loading and schema-safety.
4. Add filtersets, pagination, and action-specific serializers instead of overloading one class.
5. Cross-check response shape with `jsonapi` and any tenant/provider behavior with `prowler-api`.
6. Return the concrete DRF patterns that should be applied in code.

## Output Contract

- State which DRF layer is being guided: serializer, viewset, filterset, router, schema, or permission.
- Mention the main pattern chosen, such as split serializers, `filterset_class`, or safe `get_queryset()`.
- Name any companion skills required.
- Flag the main correctness risk: N+1, schema-generation failure, weak validation, or over-coupled serializer logic.

## References

- [Repository agent rules](../../AGENTS.md)
- [API component guidance](../../api/AGENTS.md)
- [DRF file locations](references/file-locations.md)
- [JSON:API conventions](references/json-api-conventions.md)
- [Security patterns asset](assets/security_patterns.py)
- [JSON:API skill](../jsonapi/SKILL.md)
- [Prowler API skill](../prowler-api/SKILL.md)
