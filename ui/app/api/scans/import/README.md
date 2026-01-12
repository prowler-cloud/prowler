# Scan Import API Route

API route for importing Prowler CLI scan results (JSON/OCSF and CSV formats) into the Prowler platform.

## Overview

This route handles large file uploads by streaming directly to the Django backend API, providing reliable handling for files up to 1GB.

## Endpoint

```
POST /api/scans/import
```

## Module Exports

```typescript
// Route segment configuration
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Handler
export async function POST(request: NextRequest): Promise<NextResponse>;
```

## Request Format

### Content-Type

```
multipart/form-data
```

### Form Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | File | Yes | Scan results file (JSON or CSV format) |
| `provider_id` | string (UUID) | No | UUID of existing provider to associate with |
| `create_provider` | string ("true"/"false") | No | Create provider if not found (default: "true") |

### File Requirements

- Maximum size: 1GB (1,073,741,824 bytes)
- Supported formats: JSON (OCSF), CSV (Prowler CLI output)
- MIME types: `application/json`, `text/csv`, `text/plain`

## Response Format

All responses follow the JSON:API specification.

### Success Response (201 Created)

```json
{
  "data": {
    "type": "scan-imports",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "attributes": {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "provider_id": "123e4567-e89b-12d3-a456-426614174000",
      "findings_count": 1500,
      "resources_count": 250,
      "status": "completed",
      "provider_created": false,
      "warnings": []
    }
  }
}
```

### Error Response (4xx/5xx)

```json
{
  "errors": [
    {
      "status": "400",
      "code": "invalid_format",
      "title": "Invalid file format",
      "detail": "File must be JSON or CSV format",
      "source": {
        "pointer": "/data/attributes/file"
      }
    }
  ]
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `file_too_large` | 413 | File exceeds 1GB limit |
| `invalid_format` | 400 | File is not JSON or CSV |
| `no_findings` | 400 | No findings found in file |
| `invalid_provider_id` | 400 | Provider ID format invalid |
| `provider_not_found` | 404 | Specified provider doesn't exist |
| `internal_error` | 500 | Unexpected server error |

## Usage Examples

### JavaScript/TypeScript (Browser)

```typescript
async function importScan(file: File, providerId?: string) {
  const formData = new FormData();
  formData.append("file", file);
  
  if (providerId) {
    formData.append("provider_id", providerId);
  }
  formData.append("create_provider", "true");

  const response = await fetch("/api/scans/import", {
    method: "POST",
    body: formData,
  });

  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.errors?.[0]?.detail || "Import failed");
  }
  
  return data.data.attributes;
}
```

### React Component Usage

```typescript
// From ui/components/scans/scan-import/scan-import-section.tsx
const importPromise = fetch("/api/scans/import", {
  method: "POST",
  body: formData,
}).then(async (res) => {
  const responseData = await res.json();
  if (!res.ok) {
    const firstError = responseData.errors?.[0];
    return {
      success: false as const,
      error: firstError?.detail || firstError?.title || `Import failed`,
    };
  }
  const attributes = responseData.data?.attributes;
  return {
    success: true as const,
    data: {
      scanId: attributes?.scan_id,
      providerId: attributes?.provider_id,
      findingsCount: attributes?.findings_count,
      resourcesCount: attributes?.resources_count,
      status: attributes?.status,
      providerCreated: attributes?.provider_created,
      warnings: attributes?.warnings,
    },
  };
});
```

### cURL

```bash
# Import JSON file with auto-detect provider
curl -X POST http://localhost:3000/api/scans/import \
  -F "file=@prowler-output.json" \
  -F "create_provider=true"

# Import CSV file with specific provider
curl -X POST http://localhost:3000/api/scans/import \
  -F "file=@prowler-output.csv" \
  -F "provider_id=123e4567-e89b-12d3-a456-426614174000" \
  -F "create_provider=false"
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser/UI    │────▶│  Next.js Route   │────▶│  Django API     │
│                 │     │  /api/scans/     │     │  /api/v1/scans/ │
│  FormData with  │     │  import          │     │  import         │
│  file upload    │     │                  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │                        │
                              │ getAuthHeaders()       │ ScanImportService
                              │ apiBaseUrl             │ OCSFParser/CSVParser
                              ▼                        ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │  Authentication  │     │  Database       │
                        │  JWT Token       │     │  PostgreSQL     │
                        └──────────────────┘     └─────────────────┘
```

## Implementation Details

### Route Configuration

```typescript
// Ensures Node.js runtime for file handling
export const runtime = "nodejs";

// Disables static optimization for dynamic auth
export const dynamic = "force-dynamic";
```

### File Size Validation

Early validation prevents unnecessary memory allocation:

```typescript
const contentLength = request.headers.get("content-length");
if (contentLength && parseInt(contentLength, 10) > MAX_FILE_SIZE) {
  return NextResponse.json(
    { errors: [{ title: "File too large", code: "file_too_large" }] },
    { status: 413 }
  );
}
```

### Authentication

Uses `getAuthHeaders()` from `@/lib` to obtain JWT authentication headers:

```typescript
const headers = await getAuthHeaders({ contentType: false });
```

The `contentType: false` option allows `fetch` to set the correct `multipart/form-data` boundary automatically.

### Backend Forwarding

The route forwards the request to the Django backend:

```typescript
const backendUrl = `${apiBaseUrl}/scans/import`;
const response = await fetch(backendUrl, {
  method: "POST",
  headers,
  body: formData,
});
```

## Related Files

| File | Description |
|------|-------------|
| `ui/components/scans/scan-import/` | React components for import UI |
| `ui/components/scans/scan-import/types.ts` | TypeScript type definitions |
| `api/src/backend/api/services/scan_import.py` | Backend import service |
| `api/src/backend/api/parsers/` | OCSF and CSV parsers |
| `api/src/backend/api/v1/views.py` | Django API view |

## Configuration

### Next.js (`next.config.js`)

```javascript
experimental: {
  serverActions: {
    bodySizeLimit: "1gb",
  },
}
```

### Django (`api/src/backend/config/django/base.py`)

```python
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024  # 1GB
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024 * 1024  # 1GB
```

## Testing

### E2E Tests

See `ui/tests/scan-import.spec.ts` for Playwright E2E tests covering:

- JSON file upload flow
- CSV file upload flow
- Error handling display
- Success navigation

### Manual Testing

1. Navigate to the Scans page
2. Expand the "Import Scan Results" section
3. Select a Prowler CLI output file (JSON or CSV)
4. Optionally select a provider or use auto-detect
5. Click "Import Scan Results"
6. Verify the scan appears in the list

## Troubleshooting

### File Too Large Error

If you receive a 413 error:

1. Verify file size is under 1GB
2. Check Next.js `serverActions.bodySizeLimit` configuration
3. Check Django `DATA_UPLOAD_MAX_MEMORY_SIZE` setting

### Authentication Errors

If you receive a 401/403 error:

1. Verify user is logged in
2. Check JWT token is valid
3. Verify user has `MANAGE_SCANS` permission

### Invalid Format Error

If you receive an invalid format error:

1. Verify file is valid JSON or CSV
2. For JSON: Must be OCSF format (array of findings)
3. For CSV: Must be semicolon-delimited Prowler output

## See Also

- [Scan Import Feature Spec](/.kiro/specs/scan-results-import/)
- [API Services Documentation](/api/src/backend/api/services/README.md)
- [API Configuration](/api/docs/configuration.md)
