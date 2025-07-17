# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Prowler is an open-source cloud security assessment tool supporting AWS, Azure, GCP, Kubernetes, Microsoft 365, and GitHub. It includes 900+ security checks, 50+ compliance frameworks, and both CLI and web interfaces.

## Key Commands

### Development Setup
```bash
# Install Poetry v2
pipx install poetry==2.1.1

# Install dependencies
poetry install --with dev

# Activate environment
eval $(poetry env activate)

# Install pre-commit hooks
pre-commit install
```

### Running Tests
```bash
# Run all tests with coverage
make test

# Run specific provider tests
poetry run pytest -n auto tests/providers/aws
poetry run pytest -n auto tests/providers/azure
poetry run pytest -n auto tests/providers/gcp
poetry run pytest -n auto tests/providers/kubernetes

# View coverage
make coverage-html
```

### Code Quality
```bash
# Format code
make format

# Run linters
make lint

# Type checking (for UI)
cd ui && npm run typecheck
```

### Running Prowler
```bash
# From source
python prowler-cli.py -v

# Run scans
prowler aws
prowler azure --tenant-id "your-tenant" --client-id "your-client" --client-secret "your-secret"
prowler gcp --credentials-file path/to/creds.json
prowler kubernetes --context your-context
```

### UI Development
```bash
cd ui
npm install
npm run dev  # Start development server at localhost:3000
npm run healthcheck  # Run all checks (lint, format, typecheck)
```

### API Development
```bash
cd api
poetry install
eval $(poetry env activate)

# Start dependencies
docker compose up postgres valkey -d

# Run migrations
cd src/backend
python manage.py migrate --database admin

# Start API server
gunicorn -c config/guniconf.py config.wsgi:application
```

## Architecture Overview

### Core Structure
- `/prowler/` - Main Python package with provider-specific security checks
  - `/providers/` - Cloud provider implementations (aws/, azure/, gcp/, kubernetes/, etc.)
  - `/lib/` - Core libraries (check execution, outputs, CLI parsing)
  - `/compliance/` - Compliance framework mappings
  - `/config/` - Configuration files and examples

### Provider Architecture
Each provider follows this pattern:
1. **Provider class** in `providers/{provider}/provider.py` - Authentication and session management
2. **Services** in `providers/{provider}/services/` - One directory per service
3. **Checks** in `providers/{provider}/services/{service}/{check_name}/` - Individual security checks
4. **Lib** in `providers/{provider}/lib/` - Provider-specific utilities

### Check Structure
Each check directory contains:
- `{check_name}.py` - Check implementation inheriting from base Check class
- `{check_name}.metadata.json` - Check metadata (severity, resources, remediation)
- `{check_name}_test.py` - Unit tests using pytest and mocking

### Adding New Checks
1. Create directory: `prowler/providers/{provider}/services/{service}/{check_name}/`
2. Implement check class inheriting from `Check`
3. Add metadata JSON file
4. Write unit tests
5. Map to compliance frameworks if applicable

### Output Formats
Prowler supports multiple output formats in `prowler/lib/outputs/`:
- JSON OCSF (Open Cybersecurity Schema Framework)
- CSV
- HTML
- JSON ASFF (AWS Security Hub)
- And more...

### Web Application
- **UI**: Next.js React app with TypeScript and Tailwind CSS
- **API**: Django REST Framework with Celery for async tasks
- **Database**: PostgreSQL for persistence
- **Cache**: Valkey (Redis fork) for caching and Celery broker

## Key Patterns

### Check Implementation
```python
from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class check_name(Check):
    def execute(self):
        findings = []
        for region in ec2_client.regions:
            # Check logic here
            report = Check_Report(self.metadata())
            # Set report fields
            findings.append(report)
        return findings
```

### Testing Pattern
```python
from unittest import mock
from prowler.providers.aws.services.service.service_client import ServiceClass

class Test_check_name:
    @mock.patch("prowler.providers.aws.services.service.service_client")
    def test_check_scenario(self, mock_service):
        # Mock setup
        # Execute check
        # Assert results
```

## Development Tips

1. **Provider Development**: When adding support for a new service, follow the existing pattern in other services within the same provider
2. **Check Severity**: Use appropriate severity levels (critical, high, medium, low, informational) based on security impact
3. **Testing**: Always mock external API calls; never make real cloud API calls in tests
4. **Compliance Mappings**: Update relevant compliance frameworks in `/prowler/compliance/` when adding security-relevant checks
5. **Documentation**: Update service documentation in `/docs/` when adding new features

## Common Tasks

### Adding a New AWS Service
1. Create service client in `prowler/providers/aws/services/{service}/{service}_client.py`
2. Add service class inheriting from `AWSService`
3. Implement `__list_resources__` and `__get_resource__` methods
4. Create checks in subdirectories

### Debugging Checks
```bash
# Run single check with verbose output
prowler aws --checks check_name -v

# Run with specific regions
prowler aws --checks check_name --region us-east-1 -v

# Output to specific format for debugging
prowler aws --checks check_name -M json-ocsf -v
```

### Working with Compliance
- Compliance mappings are in `prowler/compliance/{framework}/`
- Each framework has JSON files mapping requirements to checks
- Use `prowler list-compliance` to see available frameworks

## Important Notes

- Python version must be >3.9.1, <3.13
- Use Poetry for dependency management, not pip directly
- Pre-commit hooks enforce code quality - ensure they pass before committing
- The codebase follows strict typing; maintain type hints in Python code
- For UI changes, ensure TypeScript types are properly defined
- API changes require updating both Django models and TypeScript interfaces