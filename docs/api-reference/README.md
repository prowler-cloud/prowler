# Prowler API Reference Documentation

This directory contains the API reference documentation for Prowler Cloud, integrated with Mintlify.

## Structure

```
api-reference/
├── README.md                 # This file
├── openapi.yaml             # OpenAPI specification (auto-synced from api/src/backend/api/specs/v1.yaml)
├── introduction.mdx         # API introduction and getting started guide
│
├── tokens/                  # Authentication endpoints
│   ├── create.mdx          # Create JWT token
│   ├── refresh.mdx         # Refresh JWT token
│   └── switch.mdx          # Switch tenant context
│
├── api-keys/               # API Keys endpoints
│   ├── list.mdx
│   ├── create.mdx
│   ├── retrieve.mdx
│   ├── update.mdx
│   └── revoke.mdx
│
├── users/                  # User endpoints
│   └── me.mdx             # Get current user
│
├── tenants/               # Tenant management
│   ├── list.mdx
│   ├── invitations-list.mdx
│   └── invitations-create.mdx
│
├── invitations/           # Invitation endpoints
│   └── accept.mdx
│
├── providers/             # Cloud provider management
│   ├── list.mdx
│   ├── create.mdx
│   ├── retrieve.mdx
│   ├── update.mdx
│   ├── delete.mdx
│   └── check-connection.mdx
│
├── scans/                 # Security scan endpoints
│   ├── list.mdx
│   ├── retrieve.mdx
│   ├── compliance.mdx
│   ├── report.mdx
│   └── threatscore.mdx
│
├── findings/              # Security findings endpoints
│   ├── list.mdx
│   ├── retrieve.mdx
│   ├── latest.mdx
│   ├── services-regions.mdx
│   ├── metadata.mdx
│   └── metadata-latest.mdx
│
├── resources/             # Cloud resource endpoints
│   ├── list.mdx
│   ├── retrieve.mdx
│   ├── latest.mdx
│   ├── metadata.mdx
│   └── metadata-latest.mdx
│
├── compliance/            # Compliance framework endpoints
│   ├── list.mdx
│   ├── requirements.mdx
│   ├── attributes.mdx
│   └── metadata.mdx
│
├── overviews/             # Dashboard overview endpoints
│   ├── findings.mdx
│   ├── findings-severity.mdx
│   ├── providers.mdx
│   ├── providers-count.mdx
│   └── services.mdx
│
├── integrations/          # External integrations
│   ├── list.mdx
│   ├── create.mdx
│   ├── retrieve.mdx
│   ├── update.mdx
│   ├── delete.mdx
│   ├── check-connection.mdx
│   └── jira-dispatch.mdx
│
├── lighthouse/            # Lighthouse AI endpoints
│   ├── configuration-get.mdx
│   ├── configuration-update.mdx
│   ├── providers-list.mdx
│   ├── providers-create.mdx
│   └── models-list.mdx
│
├── processors/            # Finding processors (mutelists)
│   ├── list.mdx
│   └── create.mdx
│
├── schedules/             # Automated scan scheduling
│   └── daily.mdx
│
└── tasks/                 # Asynchronous task management
    ├── list.mdx
    └── retrieve.mdx
```

**Total: 131 endpoint documentation files organized in 18 groups**

✅ **100% API Coverage** - All 123 operation IDs documented

## How It Works

The API documentation uses Mintlify's native OpenAPI support to automatically generate interactive API documentation from the OpenAPI specification file.

### Components

1. **openapi.yaml**: The source of truth for API endpoints, copied from `api/src/backend/api/specs/v1.yaml`
2. **MDX files**: Enhanced documentation for each endpoint with examples, tips, and additional context
3. **docs.json**: Mintlify configuration that references the OpenAPI spec

## Updating the Documentation

### When the API Spec Changes

When you update the OpenAPI specification in `api/src/backend/api/specs/v1.yaml`, you need to sync it to the docs:

```bash
# From the root of the repository
cp api/src/backend/api/specs/v1.yaml docs/api-reference/openapi.yaml
```

Consider automating this with a pre-commit hook or CI/CD pipeline.

### Adding New Endpoints

To document a new API endpoint:

1. **Update the OpenAPI spec** in `api/src/backend/api/specs/v1.yaml`
2. **Sync to docs**: Copy the spec to `docs/api-reference/openapi.yaml`
3. **Create MDX file**: Create a new `.mdx` file in the appropriate directory
4. **Update navigation**: Add the new page to `docs/docs.json` in the API Reference tab

#### MDX File Template

```mdx
---
title: "Endpoint Title"
api: "METHOD /api/v1/endpoint"
description: "Brief description of what this endpoint does."
---

Detailed description of the endpoint.

## Path Parameters

- `param` (required/optional) - Description

## Query Parameters

- `param` (required/optional) - Description

## Request Body

```json
{
  "example": "request"
}
```

## Example Request

```bash
curl -X METHOD "https://api.prowler.com/api/v1/endpoint" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/vnd.api+json"
```

## Response

Description of the response.
```

### Testing Changes Locally

To preview documentation changes locally:

```bash
cd docs
mintlify dev
```

Then open http://localhost:3000 in your browser.

## Mintlify Configuration

The API documentation is configured in `docs/docs.json`:

- **openapi**: Points to the OpenAPI spec file
- **api.baseUrl**: The base URL for the API
- **api.auth.method**: Authentication method (bearer token)
- **api.playground.mode**: Interactive API playground mode

## API Endpoint Groups

### Core Endpoints
- **Authentication (3)**: JWT token management and tenant switching
- **API Keys (5)**: Programmatic API access management
- **Users (1)**: User profile and information
- **Tenants (3)**: Organization and invitation management

### Cloud Infrastructure
- **Providers (6)**: Cloud provider (AWS, Azure, GCP, etc.) configuration
- **Scans (5)**: Security scan execution and results
- **Findings (6)**: Security findings and vulnerabilities
- **Resources (5)**: Cloud resource inventory and metadata

### Compliance & Reporting
- **Compliance (4)**: Compliance framework assessments (CIS, PCI-DSS, etc.)
- **Overviews (5)**: Dashboard aggregated statistics

### Integrations & Automation
- **Integrations (7)**: External service integrations (S3, Security Hub, JIRA, Slack)
- **Lighthouse AI (5)**: AI-powered security insights configuration
- **Processors (2)**: Finding processors and mutelists
- **Schedules (1)**: Automated scan scheduling

### System
- **Tasks (2)**: Asynchronous task monitoring

## Best Practices

1. **Keep OpenAPI spec up to date**: Always update the source spec first, then sync to docs
2. **Add examples**: Include real-world examples in MDX files
3. **Use callouts**: Leverage Mintlify components like `<Note>`, `<Tip>`, `<Warning>` for important information
4. **Test playground**: Verify that the interactive API playground works for each endpoint
5. **Document filters**: For list endpoints, clearly document all available filters
6. **Include rate limits**: Document any rate limiting or pagination requirements
7. **Group related endpoints**: Keep related endpoints in the same directory
8. **Use consistent naming**: Follow the pattern `action.mdx` (e.g., `list.mdx`, `create.mdx`, `retrieve.mdx`)

## Resources

- [Mintlify OpenAPI Guide](https://mintlify.com/docs/api-playground/openapi-support)
- [Mintlify Components](https://mintlify.com/docs/content/components)
- [JSON:API Specification](https://jsonapi.org/)
- [Prowler Cloud API](https://api.prowler.com/api/v1/docs)

## Syncing OpenAPI Spec

The OpenAPI specification is maintained in the API repository and should be synced regularly:

```bash
# Using the provided sync script
cd docs
./sync-api-spec.sh

# Or manually
cp ../api/src/backend/api/specs/v1.yaml ./api-reference/openapi.yaml
```

The `sync-api-spec.sh` script automates this process and can be integrated into your CI/CD pipeline.

## Automation 🤖

**NEW**: Documentation can now be auto-generated from the OpenAPI specification!

### Quick Start with Automation

```bash
cd docs

# 1. Sync latest OpenAPI spec from GitHub
./sync-api-spec.sh

# 2. Generate MDX files automatically
python3 generate-api-docs.py

# 3. Test locally
mintlify dev
```

### Available Scripts

1. **`sync-api-spec.sh`** - Downloads latest OpenAPI spec from GitHub
2. **`generate-api-docs.py`** - Generates/updates MDX files from OpenAPI spec

### Features

- ✅ Auto-generate MDX files from OpenAPI spec
- ✅ Update existing or create new endpoints
- ✅ Dry-run mode to preview changes
- ✅ Proper directory structure and naming
- ✅ Frontmatter generation (title, API path, description)
- ✅ Parameter documentation extraction
- ✅ Request/response examples

### Documentation

See **[AUTOMATION.md](./AUTOMATION.md)** for complete automation guide including:
- Detailed usage instructions
- CI/CD integration examples
- Troubleshooting
- Best practices

## Recent Updates

### January 2025 - Complete API Documentation & Automation

#### Documentation Expansion
- ✅ **100% Coverage**: All 123 operation IDs documented (131 MDX files)
- ✅ **18 Endpoint Groups**: Complete organization
- ✅ **New Groups Added**:
  - Provider Secrets (5 endpoints)
  - Provider Groups (8 endpoints)
  - Roles (8 endpoints)
  - SAML Configuration (5 endpoints)
  - Lighthouse AI expanded (17 endpoints with nested structure)
  - Processors (5 endpoints)
  - Tasks (3 endpoints)
  - Compliance Overview (4 endpoints)
  - Overviews (5 endpoints)

#### Automation Implementation
- ✅ **Auto-generation script**: `generate-api-docs.py`
- ✅ **Sync script**: `sync-api-spec.sh`
- ✅ **Complete automation guide**: AUTOMATION.md
- ✅ **CI/CD ready**: GitHub Actions example included

#### Quality Improvements
- ✅ Field name corrections verified against OpenAPI spec
- ✅ JSON:API compliance in all examples
- ✅ Proper nested structures (Provider Secrets, Tenant Memberships/Invitations)
- ✅ Comprehensive documentation files (CORRECTIONS.md, VERIFICATION.md, IMPROVEMENTS.md)

**Total coverage increased from 14 to 131 documented endpoints (843% increase)**
