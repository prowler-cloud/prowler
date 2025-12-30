# Prowler API Models Documentation

This document provides comprehensive documentation for the Django models used in the Prowler API backend.

## Overview

The Prowler API uses Django ORM with PostgreSQL-specific features including:
- Row-Level Security (RLS) for multi-tenant data isolation
- Table partitioning for high-volume data (Findings)
- Full-text search with PostgreSQL GIN indexes
- Soft deletion patterns for data preservation

## Model Hierarchy

```
RowLevelSecurityProtectedModel (Base)
├── Provider
├── ProviderGroup
├── ProviderGroupMembership
├── ProviderSecret
├── Scan
├── Task
├── Resource
├── ResourceTag
├── ResourceTagMapping
├── Finding (+ PostgresPartitionedModel)
├── ResourceFindingMapping (+ PostgresPartitionedModel)
├── ComplianceOverview
├── ComplianceRequirementOverview
├── ComplianceOverviewSummary
├── ScanSummary
├── DailySeveritySummary
├── Role
├── Invitation
├── Integration
├── TenantAPIKey
├── SAMLConfiguration
├── MuteRule
├── Processor
└── Lighthouse* (AI/LLM configurations)

AbstractBaseUser
└── User

models.Model
├── Membership
├── SAMLToken
└── SAMLDomainIndex
```

## Core Models

### User

Custom user model with email-based authentication.

```python
from api.models import User

# Create a user
user = User.objects.create(
    name="John Doe",
    email="john@example.com",
    company_name="Acme Corp"
)

# Check tenant membership
if user.is_member_of_tenant(tenant_id):
    print("User has access")
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `name` | CharField(150) | Display name (min 3 chars) |
| `email` | EmailField | Unique, case-insensitive |
| `company_name` | CharField(150) | Optional company |
| `is_active` | BooleanField | Account status |
| `date_joined` | DateTimeField | Auto-set on creation |

### Provider

Represents a connected cloud account for security scanning.

```python
from api.models import Provider

# Create an AWS provider
provider = Provider.objects.create(
    tenant=tenant,
    provider=Provider.ProviderChoices.AWS,
    uid="123456789012",
    alias="Production Account"
)

# Query active providers only (default)
active_providers = Provider.objects.all()

# Include soft-deleted providers
all_providers = Provider.all_objects.all()
```

**Supported Provider Types:**
- `aws` - Amazon Web Services
- `azure` - Microsoft Azure
- `gcp` - Google Cloud Platform
- `kubernetes` - Kubernetes clusters
- `m365` - Microsoft 365
- `github` - GitHub organizations
- `mongodbatlas` - MongoDB Atlas
- `iac` - Infrastructure as Code
- `oraclecloud` - Oracle Cloud Infrastructure
- `alibabacloud` - Alibaba Cloud

**UID Validation:**
Each provider type has specific UID format requirements:
- AWS: 12-digit account ID
- Azure: Valid UUID v4
- GCP: 6-30 chars, lowercase, starts with letter
- Kubernetes: Valid UID or cluster ARN
- GitHub: 1-39 chars, alphanumeric with hyphens

### Scan

Security scan execution against a provider.

```python
from api.models import Scan, StateChoices

# Get completed scans for a provider
completed_scans = Scan.objects.filter(
    provider=provider,
    state=StateChoices.COMPLETED
).order_by('-completed_at')

# Get the latest scan
latest_scan = Scan.objects.filter(
    provider=provider,
    state=StateChoices.COMPLETED
).order_by('-inserted_at').first()
```

**Trigger Types:**
- `scheduled` - Automated scheduled scan
- `manual` - User-initiated scan
- `imported` - Created from imported data

**State Lifecycle:**
```
AVAILABLE → SCHEDULED → EXECUTING → COMPLETED
                                  ↘ FAILED
                       ↘ CANCELLED
```

### Finding

Individual security check result from a scan.

```python
from api.models import Finding, StatusChoices

# Get failed findings from a scan
failed_findings = Finding.objects.filter(
    scan=scan,
    status=StatusChoices.FAIL,
    muted=False
)

# Filter by severity
critical_findings = Finding.objects.filter(
    scan=scan,
    severity__in=['critical', 'high']
)

# Search findings
from django.contrib.postgres.search import SearchQuery
findings = Finding.objects.filter(
    text_search=SearchQuery('public access')
)
```

**Delta Values:**
- `new` - First time this finding appeared
- `changed` - Status changed from previous scan
- `None` - Unchanged from previous scan

**Note:** Finding uses PostgreSQL table partitioning on the `id` field (UUIDv7) for performance with large datasets.

### Resource

Cloud resource discovered during scans.

```python
from api.models import Resource

# Get resources with failed findings
resources_with_issues = Resource.objects.filter(
    provider=provider,
    failed_findings_count__gt=0
).order_by('-failed_findings_count')

# Search resources
resources = Resource.objects.filter(
    text_search=SearchQuery('bucket')
)

# Get resource tags
tags = resource.get_tags(tenant_id)
```

## Relationship Models

### Membership

Links users to tenants with role assignment.

```python
from api.models import Membership

# Get user's memberships
memberships = Membership.objects.filter(user=user)

# Check if user is owner
is_owner = Membership.objects.filter(
    user=user,
    tenant=tenant,
    role=Membership.RoleChoices.OWNER
).exists()
```

### ProviderGroup

Logical grouping of providers.

```python
from api.models import ProviderGroup

# Create a group
group = ProviderGroup.objects.create(
    tenant=tenant,
    name="Production Accounts"
)

# Add providers to group
group.providers.add(aws_provider, azure_provider)
```

### Role

RBAC role with granular permissions.

```python
from api.models import Role

# Create a role with specific permissions
role = Role.objects.create(
    tenant=tenant,
    name="Security Analyst",
    manage_scans=True,
    unlimited_visibility=False
)

# Assign provider groups for scoped access
role.provider_groups.add(production_group)

# Assign to users
role.users.add(user)
```

**Permission Fields:**
- `manage_users` - User management
- `manage_account` - Account settings
- `manage_billing` - Billing access
- `manage_providers` - Provider management
- `manage_integrations` - Integration configuration
- `manage_scans` - Scan execution
- `unlimited_visibility` - Access all providers

## Compliance Models

### ComplianceOverview

Aggregated compliance status per scan and framework.

```python
from api.models import ComplianceOverview

# Get compliance status for a scan
compliance = ComplianceOverview.objects.filter(
    scan=scan,
    framework='CIS'
)
```

### ComplianceRequirementOverview

Per-requirement compliance details.

```python
from api.models import ComplianceRequirementOverview

# Get failed requirements
failed_reqs = ComplianceRequirementOverview.objects.filter(
    scan=scan,
    compliance_id='cis_3_0_aws',
    requirement_status=StatusChoices.FAIL
)
```

## Integration Models

### Integration

External service integrations (S3, Security Hub, Jira, Slack).

```python
from api.models import Integration

# Create an S3 integration
integration = Integration.objects.create(
    tenant=tenant,
    integration_type=Integration.IntegrationChoices.AMAZON_S3,
    configuration={'bucket': 'my-bucket', 'region': 'us-east-1'},
    enabled=True
)
integration.credentials = {'access_key': '...', 'secret_key': '...'}
integration.save()
```

**Supported Integrations:**
- `amazon_s3` - Export findings to S3
- `aws_security_hub` - Send to Security Hub
- `jira` - Create Jira tickets
- `slack` - Slack notifications

## Security Features

### Row-Level Security (RLS)

All tenant-scoped models inherit from `RowLevelSecurityProtectedModel`, which:
- Automatically adds `tenant_id` foreign key
- Applies PostgreSQL RLS policies
- Ensures data isolation between tenants

### Encrypted Fields

Sensitive data is encrypted at rest using Fernet symmetric encryption:
- `ProviderSecret.secret` - Provider credentials
- `Integration.credentials` - Integration credentials
- `LighthouseConfiguration.api_key` - LLM API keys

```python
# Encryption is transparent via properties
provider_secret.secret = {'access_key': '...', 'secret_key': '...'}
provider_secret.save()

# Decryption happens automatically
credentials = provider_secret.secret  # Returns decrypted dict
```

### Soft Deletion

Providers use soft deletion to preserve historical data:

```python
# Soft delete a provider
provider.is_deleted = True
provider.save()

# Default manager excludes deleted
Provider.objects.all()  # Active only

# Access all including deleted
Provider.all_objects.all()
```

## Managers

### ActiveProviderManager

Filters out soft-deleted providers automatically.

```python
# Applied to: Provider, Resource, ProviderSecret, Scan, Finding, etc.
Provider.objects.all()  # Only active providers
Provider.all_objects.all()  # All providers
```

### ActiveProviderPartitionedManager

Combines partition support with active provider filtering for Finding model.

### TenantAPIKeyManager

Handles API key generation with custom prefix format.

```python
api_key = TenantAPIKey.objects.create(name="CI Key", tenant=tenant)
key_string = TenantAPIKey.objects.assign_api_key(api_key)
# Returns: "prwlr_xxxxx.generated_key_here"
```

## Enumerations

### StatusChoices
- `FAIL` - Security check failed
- `PASS` - Security check passed
- `MANUAL` - Requires manual verification

### StateChoices
- `available` - Ready for execution
- `scheduled` - Scheduled for future
- `executing` - Currently running
- `completed` - Finished successfully
- `failed` - Encountered error
- `cancelled` - Cancelled by user

### SeverityChoices
Imported from Prowler SDK: `critical`, `high`, `medium`, `low`, `informational`

## Database Indexes

Key indexes for query optimization:

| Model | Index | Purpose |
|-------|-------|---------|
| Finding | `find_tenant_scan_idx` | Scan-based queries |
| Finding | `gin_findings_search_idx` | Full-text search |
| Resource | `gin_resources_search_idx` | Full-text search |
| Scan | `scans_prov_state_ins_desc_idx` | Latest scan queries |
| ScanSummary | `ss_tenant_scan_severity_idx` | Severity aggregations |

## Migration Notes

1. **Partitioned Models**: Use `python manage.py pgmakemigrations` for Finding and ResourceFindingMapping changes.

2. **RLS Constraints**: New models inheriting from `RowLevelSecurityProtectedModel` automatically get RLS policies.

3. **Enum Fields**: Use custom enum fields (`StatusEnumField`, `SeverityEnumField`, etc.) for type safety.

## Related Documentation

- [API README](../README.md) - Setup and deployment
- [Partitions Documentation](partitions.md) - Table partitioning details
- [Parsers Documentation](../src/backend/api/parsers/README.md) - OCSF and CSV parser documentation
- [Prowler SDK](../../prowler/AGENTS.md) - Check and compliance definitions
