# Prowler API Services

This package contains business logic services for scan operations in the Prowler API.

## Overview

The services module provides high-level business logic that orchestrates database operations, parsing, and validation for scan-related functionality. Services are designed to be used by API views and handle complex multi-step operations within atomic transactions.

## Modules

### scan_import.py

Service for importing external Prowler CLI scan results (JSON/OCSF and CSV formats) into the Prowler platform.

## Quick Start

```python
from api.services import ScanImportService, ScanImportResult, ScanImportError

# Initialize service with tenant ID
service = ScanImportService(tenant_id="550e8400-e29b-41d4-a716-446655440000")

# Import scan from file content
try:
    result = service.import_scan(
        file_content=file_bytes,
        provider_id=None,  # Auto-detect or create provider
        create_provider=True
    )
    print(f"Imported {result.findings_count} findings")
    print(f"Scan ID: {result.scan_id}")
except ScanImportError as e:
    print(f"Import failed: {e.message} (code: {e.code})")
```

---

## ScanImportService

Main service class for importing Prowler scan results.

### Class Signature

```python
class ScanImportService:
    def __init__(self, tenant_id: str) -> None: ...
    
    def import_scan(
        self,
        file_content: bytes,
        provider_id: UUID | str | None = None,
        create_provider: bool = True,
    ) -> ScanImportResult: ...
```

### Constructor

```python
ScanImportService(tenant_id: str)
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant_id` | `str` | UUID string of the tenant performing the import |

**Example:**
```python
service = ScanImportService(tenant_id="550e8400-e29b-41d4-a716-446655440000")
```

### Methods

#### import_scan()

Main entry point for importing scan results. Handles format detection, parsing, provider resolution, and bulk database operations within an atomic transaction.

```python
def import_scan(
    self,
    file_content: bytes,
    provider_id: UUID | str | None = None,
    create_provider: bool = True,
) -> ScanImportResult
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_content` | `bytes` | *required* | Raw bytes of the scan file (JSON or CSV) |
| `provider_id` | `UUID \| str \| None` | `None` | Optional UUID of existing provider to associate with |
| `create_provider` | `bool` | `True` | If True, create provider if not found |

**Returns:**
- `ScanImportResult` - Result object containing scan ID, counts, and warnings

**Raises:**
- `ScanImportError` - If import fails due to validation or processing errors

**Example:**
```python
# Import with auto-detected provider
result = service.import_scan(file_content=json_bytes)

# Import with specific provider
result = service.import_scan(
    file_content=csv_bytes,
    provider_id="123e4567-e89b-12d3-a456-426614174000"
)

# Import without creating new provider
result = service.import_scan(
    file_content=json_bytes,
    create_provider=False  # Raises error if provider not found
)
```

### Internal Methods

These methods are used internally by `import_scan()` and are not part of the public API:

| Method | Description |
|--------|-------------|
| `_detect_format(content: bytes) -> str` | Detect file format (json/csv) |
| `_parse_content(content: bytes, file_format: str) -> list[ParsedFinding]` | Parse content based on format |
| `_resolve_provider(findings, provider_id, create_provider) -> tuple[Provider, bool]` | Find or create provider |
| `_create_scan(findings, provider) -> Scan` | Create scan record |
| `_bulk_create_resources(findings, provider) -> dict[str, Resource]` | Bulk create resources |
| `_bulk_create_findings(findings, scan, resources_map) -> int` | Bulk create findings |
| `_create_resource_finding_mappings(findings, pairs, resources_map) -> None` | Create resource-finding mappings |
| `_build_check_metadata(finding) -> dict[str, Any]` | Build check metadata dictionary |
| `_get_resource_uids(finding) -> list[str]` | Extract resource UIDs from finding |
| `_get_impact_extended(finding) -> str` | Get impact extended text |
| `_get_raw_result(finding) -> dict[str, Any]` | Get raw result data |
| `_get_muted_status(finding) -> bool` | Get muted status |

---

## ScanImportResult

Dataclass representing the result of a scan import operation.

### Class Signature

```python
@dataclass
class ScanImportResult:
    scan_id: UUID
    provider_id: UUID
    findings_count: int
    resources_count: int
    provider_created: bool = False
    warnings: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]: ...
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `scan_id` | `UUID` | UUID of the created scan |
| `provider_id` | `UUID` | UUID of the associated provider |
| `findings_count` | `int` | Number of findings imported |
| `resources_count` | `int` | Number of unique resources created/resolved |
| `provider_created` | `bool` | Whether a new provider was created |
| `warnings` | `list[str]` | List of warning messages (non-fatal issues) |

### Methods

#### to_dict()

Convert result to dictionary for API responses.

```python
def to_dict(self) -> dict[str, Any]
```

**Returns:**
```python
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "provider_id": "123e4567-e89b-12d3-a456-426614174000",
    "findings_count": 1500,
    "resources_count": 250,
    "provider_created": True,
    "warnings": []
}
```

---

## ScanImportError

Exception raised when scan import fails.

### Class Signature

```python
class ScanImportError(Exception):
    def __init__(
        self,
        message: str,
        code: str = "import_error",
        details: dict[str, Any] | None = None,
    ) -> None: ...
    
    def to_dict(self) -> dict[str, Any]: ...
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `message` | `str` | Human-readable error message |
| `code` | `str` | Machine-readable error code |
| `details` | `dict[str, Any]` | Additional error context |

### Error Codes

| Code | Description |
|------|-------------|
| `file_too_large` | File exceeds maximum size limit (1GB) |
| `invalid_format` | File format not recognized (not JSON or CSV) |
| `no_findings` | No findings found in the imported file |
| `invalid_provider_id` | Provider ID format is invalid |
| `provider_not_found` | Specified provider does not exist |
| `invalid_provider_type` | Provider type from file is not supported |
| `json_parse_error` | Failed to parse JSON/OCSF content |
| `csv_parse_error` | Failed to parse CSV content |
| `unsupported_format` | Internal error - unsupported format string |

### Methods

#### to_dict()

Convert error to dictionary for API responses.

```python
def to_dict(self) -> dict[str, Any]
```

**Returns:**
```python
{
    "message": "File size exceeds maximum of 1024MB",
    "code": "file_too_large",
    "details": {"size": 1500000000, "max_size": 1073741824}
}
```

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `BULK_CREATE_BATCH_SIZE` | `500` | Batch size for bulk database operations |
| `MAX_FILE_SIZE` | `1073741824` (1GB) | Maximum allowed file size for imports |

---

## Type Aliases

```python
ParsedFinding = OCSFFinding | CSVFinding
```

Union type representing a parsed finding from either OCSF JSON or CSV format.

---

## Usage Examples

### Basic Import

```python
from api.services import ScanImportService, ScanImportError

service = ScanImportService(tenant_id="550e8400-...")

# Read file content
with open("prowler-output.json", "rb") as f:
    content = f.read()

try:
    result = service.import_scan(file_content=content)
    print(f"✓ Imported {result.findings_count} findings")
    print(f"✓ Created {result.resources_count} resources")
    print(f"✓ Scan ID: {result.scan_id}")
except ScanImportError as e:
    print(f"✗ Import failed: {e.message}")
    print(f"  Code: {e.code}")
    print(f"  Details: {e.details}")
```

### Import with Existing Provider

```python
from uuid import UUID

result = service.import_scan(
    file_content=content,
    provider_id=UUID("123e4567-e89b-12d3-a456-426614174000"),
    create_provider=False  # Don't create if not found
)
```

### Import from API View

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from api.services import ScanImportService, ScanImportError

class ScanImportView(APIView):
    def post(self, request):
        file = request.FILES.get("file")
        if not file:
            return Response({"error": "No file provided"}, status=400)
        
        service = ScanImportService(tenant_id=str(request.tenant.id))
        
        try:
            result = service.import_scan(
                file_content=file.read(),
                provider_id=request.data.get("provider_id"),
                create_provider=request.data.get("create_provider", True),
            )
            return Response(result.to_dict(), status=201)
        except ScanImportError as e:
            return Response(e.to_dict(), status=400)
```

### Handling Warnings

```python
result = service.import_scan(file_content=content)

if result.warnings:
    print("Import completed with warnings:")
    for warning in result.warnings:
        print(f"  ⚠ {warning}")
```

---

## Supported File Formats

### JSON/OCSF Format

The service accepts Prowler's default JSON output in OCSF (Open Cybersecurity Schema Framework) format:

```json
[
  {
    "finding_info": {
      "uid": "prowler-aws-iam_user_mfa_enabled_console_access-...",
      "title": "IAM User MFA Enabled for Console Access"
    },
    "status": "FAIL",
    "severity": "high",
    "cloud": {
      "provider": "aws",
      "account": {
        "uid": "123456789012",
        "name": "my-account"
      }
    },
    "resources": [...]
  }
]
```

### CSV Format

The service accepts Prowler's CSV output (semicolon-delimited):

```csv
ASSESSMENT_START_TIME;FINDING_UID;PROVIDER;CHECK_ID;STATUS;...
2024-01-15T10:30:00Z;prowler-aws-...;aws;iam_user_mfa_enabled;FAIL;...
```

---

## Database Operations

The service performs the following database operations within an atomic transaction:

1. **Provider Resolution**: Find existing or create new provider
2. **Scan Creation**: Create scan record with `IMPORTED` trigger type
3. **Resource Creation**: Bulk create/resolve unique resources
4. **Finding Creation**: Bulk create findings with metadata
5. **Mapping Creation**: Create resource-finding relationships

All operations use batch sizes of 500 records for optimal performance.

---

## Error Handling

The service provides detailed error information through `ScanImportError`:

```python
try:
    result = service.import_scan(file_content=content)
except ScanImportError as e:
    # Log structured error
    logger.error(
        "Scan import failed",
        extra={
            "error_code": e.code,
            "error_message": e.message,
            "error_details": e.details,
        }
    )
    
    # Return API response
    return Response({
        "errors": [{
            "title": "Import Error",
            "detail": e.message,
            "code": e.code,
            "source": e.details,
        }]
    }, status=400)
```

---

## Performance Considerations

- **File Size Limit**: Maximum 1GB to accommodate large enterprise scans
- **Batch Operations**: Uses bulk_create with batch_size=500 for efficiency
- **Resource Deduplication**: Existing resources are reused, not duplicated
- **Atomic Transactions**: All operations succeed or fail together
- **RLS Context**: Operations run within tenant's Row-Level Security context

---

## Related Modules

- `api.parsers` - OCSF and CSV parsing functionality
- `api.models` - Database models (Scan, Finding, Resource, Provider)
- `api.v1.views` - API views that use this service
- `api.db_utils` - Database utilities including RLS transaction context

---

## See Also

- [Parsers README](../parsers/README.md) - Parser documentation
- [API Models Documentation](../../docs/models.md) - Database model documentation
- [Scan Import Spec](/.kiro/specs/scan-results-import/) - Feature specification
