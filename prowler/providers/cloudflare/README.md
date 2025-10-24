# Cloudflare Provider for Prowler

This directory contains the Cloudflare provider implementation for Prowler, enabling Cloud Security Posture Management (CSPM) for Cloudflare infrastructure.

## Overview

The Cloudflare provider allows Prowler to scan and assess the security posture of your Cloudflare zones, firewall rules, SSL/TLS settings, and other security configurations.

## Authentication

The Cloudflare provider supports two authentication methods:

### 1. API Token (Recommended)

Create an API token with the necessary permissions at https://dash.cloudflare.com/profile/api-tokens

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"
prowler cloudflare
```

Or pass it directly:

```bash
prowler cloudflare --api-token "your-api-token"
```

### 2. API Key + Email

Use your Global API Key and email:

```bash
export CLOUDFLARE_API_KEY="your-api-key"
export CLOUDFLARE_API_EMAIL="your@email.com"
prowler cloudflare
```

Or pass them directly:

```bash
prowler cloudflare --api-key "your-api-key" --api-email "your@email.com"
```

## Scoping

You can scope your scan to specific accounts or zones:

```bash
# Scan specific zones
prowler cloudflare --zone-id zone_id_1 zone_id_2

# Scan specific accounts
prowler cloudflare --account-id account_id_1 account_id_2
```

## Available Services

The Cloudflare provider currently includes the following services:

- **firewall**: Firewall rules and Web Application Firewall (WAF) settings
- **ssl**: SSL/TLS configuration and certificate settings

## Security Checks

### Firewall Service

- `firewall_waf_enabled`: Ensures Web Application Firewall (WAF) is enabled for zones

### SSL Service

- `ssl_tls_minimum_version`: Ensures minimum TLS version is set to 1.2 or higher
- `ssl_always_use_https`: Ensures 'Always Use HTTPS' is enabled for automatic HTTP to HTTPS redirects

## Directory Structure

```
cloudflare/
├── cloudflare_provider.py       # Main provider class
├── models.py                     # Cloudflare-specific models
├── exceptions/                   # Cloudflare-specific exceptions
│   └── exceptions.py
├── lib/
│   ├── arguments/               # CLI argument definitions
│   ├── mutelist/                # Mutelist functionality
│   └── service/                 # Base service class
└── services/                    # Cloudflare services
    ├── firewall/                # Firewall service and checks
    │   ├── firewall_service.py
    │   ├── firewall_client.py
    │   └── firewall_waf_enabled/
    └── ssl/                     # SSL/TLS service and checks
        ├── ssl_service.py
        ├── ssl_client.py
        ├── ssl_tls_minimum_version/
        └── ssl_always_use_https/
```

## Usage Examples

### Basic Scan

```bash
prowler cloudflare
```

### Scan with API Token

```bash
prowler cloudflare --api-token "your-api-token"
```

### Scan Specific Zones

```bash
prowler cloudflare --zone-id zone_123 zone_456
```

### Run Specific Checks

```bash
prowler cloudflare -c ssl_tls_minimum_version ssl_always_use_https
```

### Generate JSON Output

```bash
prowler cloudflare -o json
```

## Required Permissions

For the API token, you need the following permissions:

- **Zone:Read** - To list and read zone information
- **Zone Settings:Read** - To read zone settings including SSL/TLS configurations
- **Firewall Services:Read** - To read firewall rules and WAF settings
- **User:Read** - To verify authentication

## Adding New Checks

To add a new security check:

1. Create a new directory under the appropriate service (e.g., `services/firewall/new_check_name/`)
2. Create the check file: `new_check_name.py`
3. Create the metadata file: `new_check_name.metadata.json`
4. Implement the check class inheriting from `Check`
5. Use `CheckReportCloudflare` for findings

Example check structure:

```python
from typing import List
from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.service_name.service_client import service_client

class check_name(Check):
    def execute(self) -> List[CheckReportCloudflare]:
        findings = []
        for resource_id, resource in service_client.resources.items():
            report = CheckReportCloudflare(metadata=self.metadata(), resource=resource)
            # Implement your check logic here
            findings.append(report)
        return findings
```

## Contributing

When contributing new services or checks:

1. Follow the existing directory structure
2. Include comprehensive metadata for each check
3. Add appropriate error handling
4. Update this README with new services/checks
5. Test thoroughly with various Cloudflare configurations

## Support

For issues, questions, or contributions, please refer to the main Prowler repository.
