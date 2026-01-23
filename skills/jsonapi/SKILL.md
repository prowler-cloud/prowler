---
name: jsonapi
description: >
  Strict JSON:API v1.1 specification compliance.
  Trigger: When creating or modifying API endpoints, reviewing API responses, or validating JSON:API compliance.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0.0"
  scope: [root, api]
  auto_invoke:
    - "Creating API endpoints"
    - "Modifying API responses"
    - "Reviewing JSON:API compliance"
---

## Use With django-drf

This skill focuses on **spec compliance**. For **implementation patterns** (ViewSets, Serializers, Filters), use `django-drf` skill together with this one.

| Skill | Focus |
|-------|-------|
| `jsonapi` | What the spec requires (MUST/MUST NOT rules) |
| `django-drf` | How to implement it in DRF (code patterns) |

**When creating/modifying endpoints, invoke BOTH skills.**

---

## Before Implementing/Reviewing

**ALWAYS validate against the latest spec** before creating or modifying endpoints:

### Option 1: Context7 MCP (Preferred)

If Context7 MCP is available, query the JSON:API spec directly:

```
mcp_context7_resolve-library-id(query="jsonapi specification")
mcp_context7_query-docs(libraryId="<resolved-id>", query="[specific topic: relationships, errors, etc.]")
```

### Option 2: WebFetch (Fallback)

If Context7 is not available, fetch from the official spec:

```
WebFetch(url="https://jsonapi.org/format/", prompt="Extract rules for [specific topic]")
```

This ensures compliance with the latest JSON:API version, even after spec updates.

---

## Critical Rules (NEVER Break)

### Document Structure
- NEVER include both `data` and `errors` in the same response
- ALWAYS include at least one of: `data`, `errors`, `meta`
- ALWAYS use `type` and `id` (string) in resource objects
- NEVER include `id` when creating resources (server generates it)

### Content-Type
- ALWAYS use `Content-Type: application/vnd.api+json`
- ALWAYS use `Accept: application/vnd.api+json`
- NEVER add parameters to media type without `ext`/`profile`

### Resource Objects
- ALWAYS use **string** for `id` (even if UUID)
- ALWAYS use **lowercase kebab-case** for `type`
- NEVER put `id` or `type` inside `attributes`
- NEVER include foreign keys in `attributes` - use `relationships`

### Relationships
- ALWAYS include at least one of: `links`, `data`, or `meta`
- ALWAYS use resource linkage format: `{"type": "...", "id": "..."}`
- NEVER use raw IDs in relationships - always use linkage objects

### Error Objects
- ALWAYS return errors as array: `{"errors": [...]}`
- ALWAYS include `status` as **string** (e.g., `"400"`, not `400`)
- ALWAYS include `source.pointer` for field-specific errors

---

## HTTP Status Codes (Mandatory)

| Operation | Success | Async | Conflict | Not Found | Forbidden | Bad Request |
|-----------|---------|-------|----------|-----------|-----------|-------------|
| **GET** | `200` | - | - | `404` | `403` | `400` |
| **POST** | `201` | `202` | `409` | `404` | `403` | `400` |
| **PATCH** | `200` | `202` | `409` | `404` | `403` | `400` |
| **DELETE** | `200`/`204` | `202` | - | `404` | `403` | - |

### When to Use Each

| Code | Use When |
|------|----------|
| `200 OK` | Successful GET, PATCH with response body, DELETE with response |
| `201 Created` | POST created resource (MUST include `Location` header) |
| `202 Accepted` | Async operation started (return task reference) |
| `204 No Content` | Successful DELETE, PATCH with no response body |
| `400 Bad Request` | Invalid query params, malformed request, unknown fields |
| `403 Forbidden` | Authentication ok but no permission, client-generated ID rejected |
| `404 Not Found` | Resource doesn't exist OR RLS hides it (never reveal which) |
| `409 Conflict` | Duplicate ID, type mismatch, relationship conflict |
| `415 Unsupported` | Wrong Content-Type header |

---

## Document Structure

### Success Response (Single)

```json
{
  "data": {
    "type": "providers",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "attributes": {
      "alias": "Production",
      "connected": true
    },
    "relationships": {
      "tenant": {
        "data": {"type": "tenants", "id": "..."}
      }
    },
    "links": {
      "self": "/api/v1/providers/550e8400-..."
    }
  },
  "links": {
    "self": "/api/v1/providers/550e8400-..."
  }
}
```

### Success Response (List)

```json
{
  "data": [
    {"type": "providers", "id": "...", "attributes": {...}},
    {"type": "providers", "id": "...", "attributes": {...}}
  ],
  "links": {
    "self": "/api/v1/providers?page[number]=1",
    "first": "/api/v1/providers?page[number]=1",
    "last": "/api/v1/providers?page[number]=5",
    "prev": null,
    "next": "/api/v1/providers?page[number]=2"
  },
  "meta": {
    "pagination": {"count": 100, "pages": 5}
  }
}
```

### Error Response

```json
{
  "errors": [
    {
      "status": "400",
      "code": "invalid",
      "title": "Invalid attribute",
      "detail": "UID must be 12 digits for AWS accounts",
      "source": {"pointer": "/data/attributes/uid"}
    }
  ]
}
```

---

## Query Parameters

| Family | Format | Example |
|--------|--------|---------|
| `page` | `page[number]`, `page[size]` | `?page[number]=2&page[size]=25` |
| `filter` | `filter[field]`, `filter[field__op]` | `?filter[status]=FAIL` |
| `sort` | Comma-separated, `-` for desc | `?sort=-inserted_at,name` |
| `fields` | `fields[type]` | `?fields[providers]=id,alias` |
| `include` | Comma-separated paths | `?include=provider,scan.task` |

### Rules

- MUST return `400` for unsupported query parameters
- MUST return `400` for unsupported `include` paths
- MUST return `400` for unsupported `sort` fields
- MUST NOT include extra fields when `fields[type]` is specified

---

## Common Violations (AVOID)

| Violation | Wrong | Correct |
|-----------|-------|---------|
| ID as integer | `"id": 123` | `"id": "123"` |
| Type as camelCase | `"type": "providerGroup"` | `"type": "provider-groups"` |
| FK in attributes | `"tenant_id": "..."` | `"relationships": {"tenant": {...}}` |
| Errors not array | `{"error": "..."}` | `{"errors": [{"detail": "..."}]}` |
| Status as number | `"status": 400` | `"status": "400"` |
| Data + errors | `{"data": ..., "errors": ...}` | Only one or the other |
| Missing pointer | `{"detail": "Invalid"}` | `{"detail": "...", "source": {"pointer": "..."}}` |

---

## Relationship Updates

### To-One Relationship

```http
PATCH /api/v1/providers/123/relationships/tenant
Content-Type: application/vnd.api+json

{"data": {"type": "tenants", "id": "456"}}
```

To clear: `{"data": null}`

### To-Many Relationship

| Operation | Method | Body |
|-----------|--------|------|
| Replace all | PATCH | `{"data": [{...}, {...}]}` |
| Add members | POST | `{"data": [{...}]}` |
| Remove members | DELETE | `{"data": [{...}]}` |

---

## Compound Documents (`include`)

When using `?include=provider`:

```json
{
  "data": {
    "type": "scans",
    "id": "...",
    "relationships": {
      "provider": {
        "data": {"type": "providers", "id": "prov-123"}
      }
    }
  },
  "included": [
    {
      "type": "providers",
      "id": "prov-123",
      "attributes": {"alias": "Production"}
    }
  ]
}
```

### Rules

- Every included resource MUST be reachable via relationship chain from primary data
- MUST NOT include orphan resources
- MUST NOT duplicate resources (same type+id)

---

## Spec Reference

- **Full Specification**: https://jsonapi.org/format/
- **Implementation**: Use `django-drf` skill for DRF-specific patterns
- **Testing**: Use `prowler-test-api` skill for test patterns
