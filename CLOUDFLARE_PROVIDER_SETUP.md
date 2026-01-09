# Cloudflare Provider Setup Guide

This guide provides instructions for setting up and using the Cloudflare provider in Prowler.

## Overview

The Cloudflare provider has been successfully integrated into Prowler, enabling comprehensive Cloud Security Posture Management (CSPM) for Cloudflare infrastructure. This integration follows Prowler's architecture patterns and includes authentication, service discovery, and security checks.

## What Has Been Implemented

### 1. Core Provider Infrastructure

- **Provider Class** (`cloudflare_provider.py`): Main provider implementation with authentication and identity management
- **Models** (`models.py`): Cloudflare-specific data models for sessions, identity, and output options
- **Exceptions** (`exceptions/`): Custom exception handling for Cloudflare-specific errors
- **Check Report Model**: Added `CheckReportCloudflare` to `prowler/lib/check/models.py`

### 2. Authentication

The provider supports two authentication methods:

1. **API Token** (Recommended)
   - Single token with scoped permissions
   - More secure and granular control

2. **API Key + Email**
   - Legacy authentication method
   - Requires Global API Key and account email

### 3. Services Implemented

#### Firewall Service
- Lists all zones and their firewall configurations
- Retrieves firewall rules and WAF settings
- Models: `Zone`, `FirewallRule`

#### SSL/TLS Service
- Lists all zones with SSL/TLS configurations
- Retrieves SSL mode, minimum TLS version, and security settings
- Models: `Zone`, `SSLSettings`

### 4. Security Checks

Three production-ready security checks have been implemented:

1. **firewall_waf_enabled**
   - Ensures Web Application Firewall (WAF) is enabled
   - Severity: High
   - Checks for protection against OWASP Top 10 vulnerabilities

2. **ssl_tls_minimum_version**
   - Ensures minimum TLS version is 1.2 or higher
   - Severity: High
   - Protects against outdated TLS vulnerabilities

3. **ssl_always_use_https**
   - Ensures automatic HTTP to HTTPS redirection
   - Severity: Medium
   - Prevents unencrypted connections

### 5. Integration Points

- **Provider Registry**: Updated `prowler/providers/common/provider.py` to include Cloudflare initialization
- **CLI Arguments**: Full argument parser implementation in `lib/arguments/arguments.py`
- **Mutelist Support**: Cloudflare-specific mutelist implementation
- **Service Base Class**: Reusable base class for all Cloudflare services with API client functionality

## Installation

No additional installation is required. The Cloudflare provider is now part of Prowler's provider ecosystem.

### Dependencies

The Cloudflare provider uses standard Python libraries already included in Prowler:
- `requests` - For HTTP API calls
- `pydantic` - For data validation
- `colorama` - For colored output

## Quick Start

### 1. Set Up Authentication

#### Option A: Using API Token (Recommended)

```bash
export CLOUDFLARE_API_TOKEN="your-api-token-here"
```

To create an API token:
1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Click "Create Token"
3. Use the "Read all resources" template or create a custom token with:
   - Zone:Read
   - Zone Settings:Read
   - Firewall Services:Read
   - User:Read

#### Option B: Using API Key + Email

```bash
export CLOUDFLARE_API_KEY="your-global-api-key"
export CLOUDFLARE_API_EMAIL="your@email.com"
```

### 2. Run Your First Scan

```bash
# Basic scan
prowler cloudflare

# Scan specific zones
prowler cloudflare --zone-id abc123 def456

# Run specific checks
prowler cloudflare -c ssl_tls_minimum_version ssl_always_use_https

# Generate JSON output
prowler cloudflare -o json
```

### 3. Test the Connection

```bash
# This will verify your credentials
prowler cloudflare --test-connection
```

## Usage Examples

### Scan All Zones in Your Account

```bash
prowler cloudflare --api-token "your-token"
```

### Scan Specific Zones

```bash
prowler cloudflare --zone-id zone_abc123 zone_def456
```

### Run Only SSL/TLS Checks

```bash
prowler cloudflare -c ssl_tls_minimum_version ssl_always_use_https
```

### Generate Multiple Output Formats

```bash
prowler cloudflare -o json html csv
```

### Use Mutelist to Suppress Findings

Create a mutelist file `cloudflare_mutelist.yaml`:

```yaml
Accounts:
  "*":
    Checks:
      ssl_always_use_https:
        Resources:
          - "zone_123"  # Suppress for specific zone
```

Then run:

```bash
prowler cloudflare --mutelist-file cloudflare_mutelist.yaml
```

## Architecture Overview

```
cloudflare/
├── cloudflare_provider.py       # Main provider class
│   ├── Authentication handling
│   ├── Identity discovery
│   └── Session management
│
├── models.py                     # Data models
│   ├── CloudflareSession
│   ├── CloudflareIdentityInfo
│   └── CloudflareOutputOptions
│
├── exceptions/                   # Error handling
│   └── exceptions.py
│
├── lib/
│   ├── arguments/               # CLI arguments
│   ├── mutelist/                # Mutelist support
│   └── service/                 # Base service class
│       └── service.py           # API client, pagination, error handling
│
└── services/                    # Cloudflare services
    ├── firewall/
    │   ├── firewall_service.py  # Zone & firewall rule discovery
    │   ├── firewall_client.py   # Global client instance
    │   └── firewall_waf_enabled/  # Check implementation
    │
    └── ssl/
        ├── ssl_service.py       # SSL/TLS settings discovery
        ├── ssl_client.py        # Global client instance
        ├── ssl_tls_minimum_version/
        └── ssl_always_use_https/
```

## Adding New Checks

To extend the Cloudflare provider with additional checks:

### 1. Identify the Service

Determine which Cloudflare service your check belongs to (e.g., DNS, Workers, Access).

### 2. Create the Service (if needed)

If the service doesn't exist:

```bash
mkdir -p prowler/providers/cloudflare/services/dns
touch prowler/providers/cloudflare/services/dns/__init__.py
```

Create `dns_service.py`:

```python
from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from pydantic.v1 import BaseModel

class DNS(CloudflareService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.dns_records = self._list_dns_records()

    def _list_dns_records(self) -> dict:
        logger.info("DNS - Listing DNS Records...")
        records = {}
        # Implement your logic
        return records

class DNSRecord(BaseModel):
    id: str
    name: str
    type: str
    # Add other fields
```

Create `dns_client.py`:

```python
from prowler.providers.common.provider import Provider
from prowler.providers.cloudflare.services.dns.dns_service import DNS

dns_client = DNS(Provider.get_global_provider())
```

### 3. Create the Check

```bash
mkdir prowler/providers/cloudflare/services/dns/dns_dnssec_enabled
```

Create `dns_dnssec_enabled.py`:

```python
from typing import List
from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.dns.dns_client import dns_client

class dns_dnssec_enabled(Check):
    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        for zone_id, zone in dns_client.zones.items():
            report = CheckReportCloudflare(metadata=self.metadata(), resource=zone)
            report.status = "FAIL"
            report.status_extended = f"Zone {zone.name} does not have DNSSEC enabled."

            if zone.dnssec_enabled:
                report.status = "PASS"
                report.status_extended = f"Zone {zone.name} has DNSSEC enabled."

            findings.append(report)
        return findings
```

Create `dns_dnssec_enabled.metadata.json`:

```json
{
  "Provider": "cloudflare",
  "CheckID": "dns_dnssec_enabled",
  "CheckTitle": "Ensure DNSSEC is enabled for zones",
  "CheckType": [],
  "ServiceName": "dns",
  "SubServiceName": "",
  "ResourceIdTemplate": "zone_id",
  "Severity": "medium",
  "ResourceType": "Zone",
  "Description": "Check description here...",
  "Risk": "Risk description here...",
  "RelatedUrl": "https://developers.cloudflare.com/dns/dnssec/",
  "Remediation": {
    "Code": {
      "CLI": "cloudflare dns dnssec enable --zone-id <zone_id>",
      "NativeIaC": "",
      "Other": "Dashboard instructions...",
      "Terraform": "Terraform code..."
    },
    "Recommendation": {
      "Text": "Enable DNSSEC for all zones...",
      "Url": "https://developers.cloudflare.com/dns/dnssec/"
    }
  },
  "Categories": ["dns"],
  "DependsOn": [],
  "RelatedTo": [],
  "Notes": "Additional notes..."
}
```

## Troubleshooting

### Authentication Errors

**Problem**: `CloudflareEnvironmentVariableError`

**Solution**: Ensure your API token or API key + email are set correctly:

```bash
# Check environment variables
echo $CLOUDFLARE_API_TOKEN
echo $CLOUDFLARE_API_KEY
echo $CLOUDFLARE_API_EMAIL
```

### API Rate Limiting

**Problem**: Too many API requests

**Solution**: The provider includes built-in pagination and rate limit handling. If you encounter issues:
- Reduce scope with `--zone-id` or `--account-id`
- Use check filtering with `-c` to run fewer checks

### Permission Errors

**Problem**: API returns 403 Forbidden

**Solution**: Verify your API token has the necessary permissions:
- Zone:Read
- Zone Settings:Read
- Firewall Services:Read
- User:Read

## Next Steps

### Recommended Additions

1. **DNS Service**
   - DNSSEC status check
   - CAA record validation
   - DNS record security checks

2. **Access Service**
   - Access policy validation
   - Application security settings

3. **Workers Service**
   - Worker route configuration
   - KV namespace security

4. **Page Rules Service**
   - Security header validation
   - Redirect rule checks

5. **Rate Limiting Service**
   - Rate limiting rule validation
   - DDoS protection settings

## Testing

To test the Cloudflare provider:

```bash
# Test connection
prowler cloudflare --test-connection --api-token "your-token"

# Run all checks
prowler cloudflare

# Verify output
ls prowler-output-*
```

## Contributing

When contributing to the Cloudflare provider:

1. Follow the existing code structure
2. Include comprehensive metadata for checks
3. Add error handling and logging
4. Test with various Cloudflare configurations
5. Update documentation

## Support

For questions or issues:
- Check the main Prowler documentation
- Review the Cloudflare API documentation: https://developers.cloudflare.com/api/
- Submit issues to the Prowler GitHub repository

## Summary

The Cloudflare provider is now fully integrated into Prowler with:
- ✅ Complete authentication support (API Token + API Key/Email)
- ✅ Provider registration and initialization
- ✅ Two service implementations (Firewall, SSL)
- ✅ Three production-ready security checks
- ✅ Full CLI argument support
- ✅ Mutelist functionality
- ✅ Error handling and logging
- ✅ Comprehensive documentation

You can now start scanning your Cloudflare infrastructure for security misconfigurations!
