---
name: prowler-provider
description: >
  Creates new Prowler cloud providers or adds services to existing providers.
  Trigger: When extending Prowler SDK provider architecture (adding a new provider or a new service to an existing provider).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, sdk]
  auto_invoke:
    - "Adding new providers"
    - "Adding services to existing providers"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

Use this skill when:
- Adding a new cloud provider to Prowler
- Adding a new service to an existing provider
- Understanding the provider architecture pattern

## Provider Architecture Pattern

Every provider MUST follow this structure:

```
prowler/providers/{provider}/
├── __init__.py
├── {provider}_provider.py      # Main provider class
├── models.py                   # Provider-specific models
├── config.py                   # Provider configuration
├── exceptions/                 # Provider-specific exceptions
├── lib/
│   ├── service/               # Base service class
│   ├── arguments/             # CLI arguments parser
│   └── mutelist/              # Mutelist functionality
└── services/
    └── {service}/
        ├── {service}_service.py   # Resource fetcher
        ├── {service}_client.py    # Python singleton instance
        └── {check_name}/          # Individual checks
            ├── {check_name}.py
            └── {check_name}.metadata.json
```

## Provider Class Template

```python
from prowler.providers.common.provider import Provider

class {Provider}Provider(Provider):
    """Provider class for {Provider} cloud platform."""

    def __init__(self, arguments):
        super().__init__(arguments)
        self.session = self._setup_session(arguments)
        self.regions = self._get_regions()

    def _setup_session(self, arguments):
        """Provider-specific authentication."""
        # Implement credential handling
        pass

    def _get_regions(self):
        """Get available regions for provider."""
        # Return list of regions
        pass
```

## Service Class Template

```python
from prowler.providers.{provider}.lib.service.service import {Provider}Service

class {Service}({Provider}Service):
    """Service class for {service} resources."""

    def __init__(self, provider):
        super().__init__(provider)
        self.{resources} = []
        self._fetch_{resources}()

    def _fetch_{resources}(self):
        """Fetch {resource} data from API."""
        try:
            response = self.client.list_{resources}()
            for item in response:
                self.{resources}.append(
                    {Resource}(
                        id=item["id"],
                        name=item["name"],
                        region=item.get("region"),
                    )
                )
        except Exception as e:
            logger.error(f"Error fetching {resources}: {e}")
```

## Service Client Template

```python
from prowler.providers.{provider}.services.{service}.{service}_service import {Service}

{service}_client = {Service}
```

## Supported Providers

Current providers:
- AWS (Amazon Web Services)
- Azure (Microsoft Azure)
- GCP (Google Cloud Platform)
- Kubernetes
- GitHub
- M365 (Microsoft 365)
- OracleCloud (Oracle Cloud Infrastructure)
- AlibabaCloud
- Cloudflare
- MongoDB Atlas
- NHN (NHN Cloud)
- LLM (Language Model providers)
- IaC (Infrastructure as Code)

## Commands

```bash
# Run provider
poetry run python prowler-cli.py {provider}

# List services for provider
poetry run python prowler-cli.py {provider} --list-services

# List checks for provider
poetry run python prowler-cli.py {provider} --list-checks

# Run specific service
poetry run python prowler-cli.py {provider} --services {service}

# Debug mode
poetry run python prowler-cli.py {provider} --log-level DEBUG
```

## Resources

- **Templates**: See [assets/](assets/) for Provider, Service, and Client singleton templates
- **Documentation**: See [references/provider-docs.md](references/provider-docs.md) for official Prowler Developer Guide links
