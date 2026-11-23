# Prowler SDK Agent Guide

> **Skills Reference**: For detailed patterns, use these skills:
> - [`prowler-sdk-check`](../skills/prowler-sdk-check/SKILL.md) - Create new security checks (step-by-step)
> - [`prowler-provider`](../skills/prowler-provider/SKILL.md) - Add new cloud providers
> - [`prowler-test-sdk`](../skills/prowler-test-sdk/SKILL.md) - pytest patterns for SDK
> - [`prowler-compliance`](../skills/prowler-compliance/SKILL.md) - Compliance framework structure
> - [`pytest`](../skills/pytest/SKILL.md) - Generic pytest patterns

## Auto-invoke Skills

When performing these actions, ALWAYS invoke the corresponding skill FIRST:

| Action | Skill |
|--------|-------|
| Add changelog entry for a PR or feature | `prowler-changelog` |
| Add or edit changelog fragments in <component>/changelog.d/ | `prowler-changelog` |
| Adding ConfigRequirements guardrails to compliance requirements | `prowler-compliance` |
| Adding a compliance output formatter (per-provider class + table dispatcher) | `prowler-compliance` |
| Adding new providers | `prowler-provider` |
| Adding services to existing providers | `prowler-provider` |
| Auditing check-to-requirement mappings as a cloud auditor | `prowler-compliance` |
| Committing changes | `prowler-commit` |
| Create PR that requires changelog entry | `prowler-changelog` |
| Creating a git commit | `prowler-commit` |
| Creating a universal (multi-provider) compliance framework | `prowler-compliance` |
| Creating new checks | `prowler-sdk-check` |
| Creating/updating compliance frameworks | `prowler-compliance` |
| Fixing bug | `tdd` |
| Fixing compliance JSON bugs (duplicate IDs, empty Section, stale refs) | `prowler-compliance` |
| Implementing feature | `tdd` |
| Mapping checks to compliance controls | `prowler-compliance` |
| Mocking AWS with moto in tests | `prowler-test-sdk` |
| Modifying component | `tdd` |
| Packaging checks, compliance frameworks or providers as external packages | `prowler-registry-artifact` |
| Publishing artifacts to Prowler Registry | `prowler-registry-artifact` |
| Refactoring code | `tdd` |
| Review changelog format and conventions | `prowler-changelog` |
| Reviewing compliance framework PRs | `prowler-compliance-review` |
| Syncing compliance framework with upstream catalog | `prowler-compliance` |
| Updating existing checks and metadata | `prowler-sdk-check` |
| Working on task | `tdd` |
| Writing Prowler SDK tests | `prowler-test-sdk` |
| Writing Python tests with pytest | `pytest` |

---

## Project Overview

The Prowler SDK is the core Python engine powering cloud security assessments across AWS, Azure, GCP, Kubernetes, GitHub, M365, and more. It includes 1100+ security checks and 85+ compliance frameworks.

---

## CRITICAL RULES

### Provider Architecture

```text
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

Python 3.10+ | uv | pytest | moto (AWS mocking) | Pre-commit hooks (black, flake8, pylint, bandit)

---

## PROJECT STRUCTURE

```text
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
uv sync
uv run pre-commit install

# Run Prowler
uv run python prowler-cli.py {provider}
uv run python prowler-cli.py {provider} --check {check_name}
uv run python prowler-cli.py {provider} --list-checks

# Testing
uv run pytest -n auto -vvv tests/
uv run pytest tests/providers/{provider}/services/{service}/ -v

# Code Quality
uv run pre-commit run --all-files
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

- [ ] `uv run pytest` passes
- [ ] `uv run pre-commit run --all-files` passes
- [ ] Check metadata JSON is valid
- [ ] Tests cover PASS, FAIL, and empty resource scenarios
- [ ] Docstrings follow Google style
