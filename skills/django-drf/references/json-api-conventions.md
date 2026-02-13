# JSON:API Conventions

## Content Type

```
Content-Type: application/vnd.api+json
Accept: application/vnd.api+json
```

## Query Parameters

| Feature | Format | Example |
|---------|--------|---------|
| **Pagination** | `page[number]`, `page[size]` | `?page[number]=2&page[size]=20` |
| **Filtering** | `filter[field]`, `filter[field__lookup]` | `?filter[status]=FAIL&filter[inserted_at__gte]=2024-01-01` |
| **Sorting** | `sort` (prefix `-` for desc) | `?sort=-inserted_at,name` |
| **Sparse fields** | `fields[type]` | `?fields[providers]=id,alias,uid` |
| **Includes** | `include` | `?include=provider,scan` |
| **Search** | `filter[search]` | `?filter[search]=production` |

## Filter Naming

| Lookup | Django Filter | JSON:API Query |
|--------|--------------|----------------|
| Exact | `field` | `filter[field]=value` |
| Contains | `field__icontains` | `filter[field__icontains]=val` |
| In list | `field__in` | `filter[field__in]=a,b,c` |
| Greater/equal | `field__gte` | `filter[field__gte]=2024-01-01` |
| Less/equal | `field__lte` | `filter[field__lte]=2024-12-31` |
| Related field | `relation__field` | `filter[provider_id]=uuid` |

## Request Format

```json
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
```

## Response Format

```json
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

## Error Response Format

```json
{
  "errors": [
    {
      "detail": "Error message here",
      "status": "400",
      "source": {"pointer": "/data/attributes/field_name"},
      "code": "error_code"
    }
  ]
}
```

## Resource Naming Rules

- Use **lowercase kebab-case** (hyphens, not underscores)
- Use **plural nouns** for collections
- Resource name in `JSONAPIMeta` MUST match URL path segment

| Model | resource_name | URL Path |
|-------|---------------|----------|
| `Provider` | `providers` | `/api/v1/providers` |
| `ProviderGroup` | `provider-groups` | `/api/v1/provider-groups` |
| `ProviderSecret` | `provider-secrets` | `/api/v1/providers/secrets` |
| `ComplianceOverview` | `compliance-overviews` | `/api/v1/compliance-overviews` |
| `AttackPathsScan` | `attack-paths-scans` | `/api/v1/attack-paths-scans` |
| `TenantAPIKey` | `api-keys` | `/api/v1/api-keys` |
| `MuteRule` | `mute-rules` | `/api/v1/mute-rules` |

## URL Endpoints

| Operation | Method | URL Pattern |
|-----------|--------|-------------|
| List | GET | `/{resources}` |
| Create | POST | `/{resources}` |
| Retrieve | GET | `/{resources}/{id}` |
| Update | PATCH | `/{resources}/{id}` |
| Delete | DELETE | `/{resources}/{id}` |
| Relationship | * | `/{resources}/{id}/relationships/{relation}` |
| Nested list | GET | `/{parent}/{parent_id}/{resources}` |
