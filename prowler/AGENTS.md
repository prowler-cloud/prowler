# Prowler SDK Agent Guide

**Complete guide for AI agents and developers working on the Prowler SDK - the core Python security scanning engine.**

## Project Overview

The Prowler SDK is the core Python engine that powers Prowler's cloud security assessment capabilities. It provides:

- **Multi-cloud Security Scanning**: AWS, Azure, GCP, Kubernetes, GitHub, M365, Oracle Cloud, MongoDB Atlas, and more
- **Compliance Frameworks**: 30+ frameworks including CIS, NIST, PCI-DSS, SOC2, GDPR
- **1000+ Security Checks**: Comprehensive coverage across all supported providers
- **Multiple Output Formats**: JSON, CSV, HTML, ASFF, OCSF, and compliance-specific formats

## Mission & Scope

- Maintain and enhance the core Prowler SDK functionality with security and stability as top priorities
- Follow best practices for Python patterns, code style, security, and comprehensive testing
- To get more information about development guidelines, please refer to the Prowler Developer Guide in `docs/developer-guide/`

---

## Architecture Rules

### 1. Provider Architecture Pattern

All Prowler providers MUST follow the established pattern:

```
prowler/providers/{provider}/
├── {provider}_provider.py          # Main provider class
├── models.py                       # Provider-specific models
├── config.py                       # Provider configuration
├── exceptions/                     # Provider-specific exceptions
├── lib/                           # Provider libraries (as minimun it should have implemented the next folders: service, arguments, mutelist)
│   ├── service/                   # Provider-specific service class to be inherited by all services of the provider
│   ├── arguments/                 # Provider-specific CLI arguments parser
│   └── mutelist/                  # Provider-specific mutelist functionality
└── services/                      # All provider services to be audited
    └── {service}/                 # Individual service
        ├── {service}_service.py   # Class to fetch the needed resources from the API and store them to be used by the checks
        ├── {service}_client.py    # Python instance of the service class to be used by the checks
        └── {check_name}/          # Individual check folder
            ├── {check_name}.py    # Python class to implement the check logic
            └── {check_name}.metadata.json # JSON file to store the check metadata
        └── {check_name_2}/          # Other checks can be added to the same service folder
            ├── {check_name_2}.py
            └── {check_name_2}.metadata.json
        ...
    └── {service_2}/                 # Other services can be added to the same provider folder
        ...
```

### 2. Check Implementation Standards

Every security check MUST implement:

```python
from prowler.lib.check.models import Check, CheckReport<Provider>
from prowler.providers.<provider>.services.<service>.<service>_client import <service>_client

class check_name(Check):
    """Ensure that <resource> meets <security_requirement>."""
    def execute(self) -> list[CheckReport<Provider>]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        # Check implementation here
        for resource in <service>_client.<resources>:
            # Security validation logic
            report = CheckReport<Provider>(metadata=self.metadata(), resource=resource)
            report.status = "PASS" | "FAIL"
            report.status_extended = "Detailed explanation"
            findings.append(report) # Add the report to the list of findings
        return findings
```

### 3. Compliance Framework Integration

All compliance frameworks must be defined in:
- `prowler/compliance/{provider}/{framework}.json`
- Follow the established Compliance model structure
- Include proper requirement mappings and metadata

---

## Tech Stack

- **Language**: Python 3.9+
- **Dependency Management**: Poetry 2+
- **CLI Framework**: Custom argument parser with provider-specific subcommands
- **Testing**: Pytest with extensive unit and integration tests
- **Code Quality**: Pre-commit hooks for Black, Flake8, Pylint, Bandit for security scanning

## Commands

### Development Environment

```bash
# Core development setup
poetry install --with dev          # Install all dependencies
poetry run pre-commit install      # Install pre-commit hooks

# Code quality
poetry run pre-commit run --all-files

# Run tests
poetry run pytest -n auto -vvv -s -x tests/
```

### Running Prowler CLI

```bash
# Run Prowler
poetry run python prowler-cli.py --help

# Run Prowler with a specific provider
poetry run python prowler-cli.py <provider>

# Run Prowler with error logging
poetry run python prowler-cli.py <provider> --log-level ERROR --verbose

# Run specific checks
poetry run python prowler-cli.py <provider> --checks <check_name_1> <check_name_2>
```

## Project Structure

```
prowler/
├── __main__.py                    # Main CLI entry point
├── config/                        # Global configuration
│   ├── config.py                  # Core configuration settings
│   └── __init__.py
├── lib/                          # Core library functions
│   ├── check/                    # Check execution engine
│   │   ├── check.py              # Check execution logic
│   │   ├── checks_loader.py      # Dynamic check loading
│   │   ├── compliance.py         # Compliance framework handling
│   │   └── models.py             # Check and report models
│   ├── cli/                      # Command-line interface
│   │   └── parser.py             # Argument parsing
│   ├── outputs/                  # Output format handlers
│   │   ├── csv/                  # CSV output
│   │   ├── html/                 # HTML reports
│   │   ├── json/                 # JSON formats
│   │   └── compliance/           # Compliance reports
│   ├── scan/                     # Scan orchestration
│   ├── utils/                    # Utility functions
│   └── mutelist/                 # Mute list functionality
├── providers/                    # Cloud provider implementations
│   ├── aws/                      # AWS provider
│   ├── azure/                    # Azure provider
│   ├── gcp/                      # Google Cloud provider
│   ├── kubernetes/               # Kubernetes provider
│   ├── github/                   # GitHub provider
│   ├── m365/                     # Microsoft 365 provider
│   ├── mongodbatlas/             # MongoDB Atlas provider
│   ├── oci/                      # Oracle Cloud provider
│   ├── ...
│   └── common/                   # Shared provider utilities
├── compliance/                   # Compliance framework definitions
│   ├── aws/                      # AWS compliance frameworks
│   ├── azure/                    # Azure compliance frameworks
│   ├── gcp/                      # GCP compliance frameworks
│   ├── ...
└── exceptions/                   # Global exception definitions
```

## Key Components

### 1. Provider System

Each cloud provider implements:

```python
class Provider:
    """Base provider class"""

    def __init__(self, arguments):
        self.session = self._setup_session(arguments)
        self.regions = self._get_regions()
        # Initialize all services

    def _setup_session(self, arguments):
        """Provider-specific authentication"""
        pass

    def _get_regions(self):
        """Get available regions for provider"""
        pass
```

### 2. Check Engine

The check execution system:

- **Dynamic Loading**: Automatically discovers and loads checks
- **Parallel Execution**: Runs checks in parallel for performance
- **Error Isolation**: Individual check failures don't affect others
- **Comprehensive Reporting**: Detailed findings with remediation guidance

### 3. Compliance Framework Engine

Compliance frameworks are defined as JSON files mapping checks to requirements:

```json
{
  "Framework": "CIS",
  "Name": "CIS Amazon Web Services Foundations Benchmark v2.0.0",
  "Version": "2.0",
  "Provider": "AWS",
  "Description": "The CIS Amazon Web Services Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services with an emphasis on foundational, testable, and architecture agnostic settings.",
  "Requirements": [
    {
      "Id": "1.1",
      "Description": "Maintain current contact details",
      "Checks": ["account_contact_details_configured"]
    }
  ]
}
```

### 4. Output System

Multiple output formats supported:

- **JSON**: Machine-readable findings
- **CSV**: Spreadsheet-compatible format
- **HTML**: Interactive web reports
- **ASFF**: AWS Security Finding Format
- **OCSF**: Open Cybersecurity Schema Framework

## Development Patterns

### Adding New Cloud Providers

1. **Create Provider Structure**:
```bash
mkdir -p prowler/providers/{provider}
mkdir -p prowler/providers/{provider}/services
mkdir -p prowler/providers/{provider}/lib/{service,arguments,mutelist}
mkdir -p prowler/providers/{provider}/exceptions
```

2. **Implement Provider Class**:
```python
from prowler.providers.common.provider import Provider

class NewProvider(Provider):
    def __init__(self, arguments):
        super().__init__(arguments)
        # Provider-specific initialization
```

3. **Add Provider to CLI**:
Update `prowler/lib/cli/parser.py` to include new provider arguments.

### Adding New Security Checks

The most common high level steps to create a new check are:

1. Prerequisites:
    - Verify the check does not already exist by searching in the same service folder as `prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>/`.
    - Ensure required provider and service exist. If not, you will need to create them first.
    - Confirm the service has implemented all required methods and attributes for the check (in most cases, you will need to add or modify some methods in the service to get the data you need for the check).
2. Navigate to the service directory. The path should be as follows: `prowler/providers/<provider>/services/<service>`.
3. Create a check-specific folder. The path should follow this pattern: `prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>`. Adhere to the [Naming Format for Checks](/developer-guide/checks#naming-format-for-checks).
4. Create the check files, you can use next commands:
```bash
mkdir -p prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>
touch prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>/__init__.py
touch prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>/<check_name_want_to_implement>.py
touch prowler/providers/<provider>/services/<service>/<check_name_want_to_implement>/<check_name_want_to_implement>.metadata.json
```
5. Run the check locally to ensure it works as expected. For checking you can use the CLI in the next way:
    - To ensure the check has been detected by Prowler: `poetry run python prowler-cli.py <provider> --list-checks | grep <check_name>`.
    - To run the check, to find possible issues: `poetry run python prowler-cli.py <provider> --log-level ERROR --verbose --check <check_name>`.
6. Create comprehensive tests for the check that cover multiple scenarios including both PASS (compliant) and FAIL (non-compliant) cases. For detailed information about test structure and implementation guidelines, refer to the [Testing](/developer-guide/unit-testing) documentation.
7. If the check and its corresponding tests are working as expected, you can submit a PR to Prowler.

### Adding Compliance Frameworks

1. **Create Framework File**:
```bash
# Create prowler/compliance/{provider}/{framework}.json
```

2. **Define Requirements**:
Map framework requirements to existing checks.

3. **Test Compliance**:
```bash
poetry run python -m prowler {provider} --compliance {framework}
```

## Code Quality Standards

### 1. Python Style

- **PEP 8 Compliance**: Enforced by black and flake8
- **Type Hints**: Required for all public functions
- **Docstrings**: Required for all classes and methods
- **Import Organization**: Use isort for consistent import ordering

```python
import standard_library

from third_party import library

from prowler.lib import internal_module

class ExampleClass:
    """Class docstring."""

    def method(self, param: str) -> dict | list | None:
        """Method docstring.

        Args:
            param: Description of parameter

        Returns:
            Description of return value
        """
        return None
```

### 2. Error Handling

```python
from prowler.lib.logger import logger

try:
    # Risky operation
    result = api_call()
except ProviderSpecificException as e:
    logger.error(f"Provider error: {e}")
    # Graceful handling
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    # Never let checks crash the entire scan
```

### 3. Security Practices

- **No Hardcoded Secrets**: Use environment variables or secure credential management
- **Input Validation**: Validate all external inputs
- **Principle of Least Privilege**: Request minimal necessary permissions
- **Secure Defaults**: Default to secure configurations

## Testing Guidelines

### Unit Tests

- **100% Coverage Goal**: Aim for complete test coverage
- **Mock External Services**: Use mock objects to simulate the external services
- **Test Edge Cases**: Include error conditions and boundary cases

## References

- **Root Project Guide**: `../AGENTS.md` (takes priority for cross-component guidance)
- **Provider Examples**: Reference existing providers for implementation patterns
- **Check Examples**: Study existing checks for proper implementation patterns
- **Compliance Framework Examples**: Review existing frameworks for structure
