# Prowler SDK Agent Guide

> **Skills Reference**: For detailed patterns, use these skills:
> - [`prowler-sdk-check`](../skills/prowler-sdk-check/SKILL.md) - Create new security checks (step-by-step)
> - [`prowler-provider`](../skills/prowler-provider/SKILL.md) - Add new cloud providers
> - [`prowler-test-sdk`](../skills/prowler-test-sdk/SKILL.md) - pytest patterns for SDK
> - [`prowler-compliance`](../skills/prowler-compliance/SKILL.md) - Compliance framework structure
> - [`pytest`](../skills/pytest/SKILL.md) - Generic pytest patterns

### Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action | Skill |
|--------|-------|
| Add changelog entry for a PR or feature | `prowler-changelog` |
| Adding new providers | `prowler-provider` |
| Adding services to existing providers | `prowler-provider` |
| Create PR that requires changelog entry | `prowler-changelog` |
| Creating new checks | `prowler-sdk-check` |
| Creating/updating compliance frameworks | `prowler-compliance` |
| Mapping checks to compliance controls | `prowler-compliance` |
| Mocking AWS with moto in tests | `prowler-test-sdk` |
| Review changelog format and conventions | `prowler-changelog` |
| Reviewing compliance framework PRs | `prowler-compliance-review` |
| Update CHANGELOG.md in any component | `prowler-changelog` |
| Updating existing checks and metadata | `prowler-sdk-check` |
| Writing Prowler SDK tests | `prowler-test-sdk` |
| Writing Python tests with pytest | `pytest` |

---

## Project Overview

The Prowler SDK is the core Python engine powering cloud security assessments across AWS, Azure, GCP, Kubernetes, GitHub, M365, and more. It includes 1100+ security checks and 85+ compliance frameworks.

---

## CRITICAL RULES

### Provider Architecture

```
prowler/providers/{provider}/
├── {provider}_provider.py      # Main provider class
├── models.py                   # Provider-specific models
├── lib/                        # service/, arguments/, mutelist/
└── services/{service}/
    ├── {service}_service.py    # Resource fetcher
    ├── {service}_client.py     # Singleton instance
    └── {check_name}/           # Individual checks
        ├── {check_name}.py
        └── {check_name}.metadata.json
```

### Check Implementation

```python
from prowler.lib.check.models import Check, CheckReport{Provider}
from prowler.providers.{provider}.services.{service}.{service}_client import {service}_client

class {check_name}(Check):
    def execute(self) -> list[CheckReport{Provider}]:
        findings = []
        for resource in {service}_client.{resources}:
            report = CheckReport{Provider}(metadata=self.metadata(), resource=resource)
            report.status = "PASS" if resource.is_compliant else "FAIL"
            report.status_extended = "Detailed explanation"
            findings.append(report)
        return findings
```

### Code Style

- Type hints required for all public functions
- Docstrings required for classes and methods (Google style)
- PEP 8 compliance enforced by black/flake8
- Import order: standard → third-party → local

---

## TECH STACK

Python 3.9+ | Poetry 2+ | pytest | moto (AWS mocking) | Pre-commit hooks (black, flake8, pylint, bandit)

---

## PROJECT STRUCTURE

```
prowler/
├── __main__.py                # CLI entry point
├── config/                    # Global configuration
├── lib/
│   ├── check/                # Check execution engine
│   ├── cli/                  # Command-line interface
│   ├── outputs/              # Output format handlers (JSON, CSV, HTML, ASFF, OCSF)
│   └── mutelist/             # Mute list functionality
├── providers/                # Cloud providers (aws, azure, gcp, kubernetes, github, m365...)
│   └── common/               # Shared provider utilities
├── compliance/               # Compliance framework definitions (CIS, NIST, PCI-DSS, SOC2...)
└── exceptions/               # Global exceptions
```

---

## COMMANDS

```bash
# Setup
poetry install --with dev
poetry run pre-commit install

# Run Prowler
poetry run python prowler-cli.py {provider}
poetry run python prowler-cli.py {provider} --check {check_name}
poetry run python prowler-cli.py {provider} --list-checks

# Testing
poetry run pytest -n auto -vvv tests/
poetry run pytest tests/providers/{provider}/services/{service}/ -v

# Code Quality
poetry run pre-commit run --all-files
```

---

## CREATING NEW CHECKS (Quick Reference)

1. Verify check doesn't exist: `--list-checks | grep {check_name}`
2. Create folder: `prowler/providers/{provider}/services/{service}/{check_name}/`
3. Create files: `__init__.py`, `{check_name}.py`, `{check_name}.metadata.json`
4. Implement check logic
5. Test locally: `--check {check_name}`
6. Write tests

**For detailed guidance, use the `prowler-sdk-check` skill.**

---

## QA CHECKLIST

- [ ] `poetry run pytest` passes
- [ ] `poetry run pre-commit run --all-files` passes
- [ ] Check metadata JSON is valid
- [ ] Tests cover PASS, FAIL, and empty resource scenarios
- [ ] Docstrings follow Google style
