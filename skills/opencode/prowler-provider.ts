
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: prowler-provider
description: Creates new Prowler cloud providers or adds services to existing providers. Covers the provider architecture pattern with services, checks, and authentication.
license: Apache 2.0
---

## When to use this skill

Use this skill when:
- Adding a new cloud provider to Prowler
- Adding a new service to an existing provider
- Understanding the provider architecture pattern

## Provider Architecture Pattern

Every provider MUST follow this structure:
\`\`\`
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
\`\`\`

## Provider Class Template

\`\`\`python
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
\`\`\`

## Service Class Template

\`\`\`python
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
                        # ... other attributes
                    )
                )
        except Exception as e:
            logger.error(f"Error fetching {resources}: {e}")
\`\`\`

## Service Client Template

\`\`\`python
from prowler.providers.{provider}.services.{service}.{service}_service import {Service}

{service}_client = {Service}
\`\`\`

## Supported Providers

Current providers:
- AWS (Amazon Web Services)
- Azure (Microsoft Azure)
- GCP (Google Cloud Platform)
- Kubernetes
- GitHub
- M365 (Microsoft 365)
- OCI (Oracle Cloud Infrastructure)
- AlibabaCloud
- MongoDB Atlas
- IaC (Infrastructure as Code)

## Commands

\`\`\`bash
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
\`\`\`

## Keywords
prowler provider, cloud security, aws, azure, gcp, kubernetes, github, m365, oci, alibabacloud
`;

export default tool({
  description: SKILL,
  args: {
    provider: tool.schema.string().describe("Provider name (e.g., newcloud, customplatform)"),
    action: tool.schema.string().describe("Action: new-provider, add-service, list-structure"),
  },
  async execute(args) {
    return `
Prowler Provider Pattern for: ${args.provider} - ${args.action}

${args.action === 'new-provider' ? `
Creating new provider "${args.provider}":

1. Create directory structure:
   mkdir -p prowler/providers/${args.provider}/{services,lib/{service,arguments,mutelist},exceptions}

2. Required files:
   - prowler/providers/${args.provider}/__init__.py
   - prowler/providers/${args.provider}/${args.provider}_provider.py
   - prowler/providers/${args.provider}/models.py
   - prowler/providers/${args.provider}/config.py
   - prowler/providers/${args.provider}/lib/service/service.py
   - prowler/providers/${args.provider}/lib/arguments/arguments.py
   - prowler/providers/${args.provider}/lib/mutelist/mutelist.py

3. Update CLI parser:
   - prowler/lib/cli/parser.py

4. Test:
   poetry run python prowler-cli.py ${args.provider} --help
` : args.action === 'add-service' ? `
Adding new service to "${args.provider}":

1. Create service directory:
   mkdir -p prowler/providers/${args.provider}/services/{service_name}

2. Required files:
   - {service_name}_service.py (fetches resources)
   - {service_name}_client.py (singleton instance)
   - Check directories with .py and .metadata.json

3. Test:
   poetry run python prowler-cli.py ${args.provider} --services {service_name}
` : `
Provider structure for "${args.provider}":

prowler/providers/${args.provider}/
├── ${args.provider}_provider.py
├── models.py
├── config.py
├── exceptions/
├── lib/
│   ├── service/
│   ├── arguments/
│   └── mutelist/
└── services/
    └── {service}/
        ├── {service}_service.py
        ├── {service}_client.py
        └── {check_name}/
`}

Reference existing providers for patterns:
- AWS: Most complete, use as main reference
- Azure: Good example of complex auth
- Kubernetes: Different resource model
    `.trim()
  },
})
