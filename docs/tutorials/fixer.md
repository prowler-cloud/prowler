# Prowler Fixers (remediations)

Prowler supports automated remediation ("fixers") for certain findings. This system is extensible and provider-agnostic, allowing you to implement fixers for AWS, Azure, GCP, and M365 using a unified interface.

---

## Overview

- **Fixers** are Python classes that encapsulate the logic to remediate a failed check.
- Each provider has its own base fixer class, inheriting from a common abstract base (`Fixer`).
- Fixers are automatically discovered and invoked by Prowler when the `--fixer` flag is used.

???+ note
    Right now, fixers are only available through the CLI.

---

## How to Use Fixers

To run fixers for failed findings:

```sh
prowler <provider> -c <check_id_1> <check_id_2> ... --fixer
```

To list all available fixers for a provider:

```sh
prowler <provider> --list-fixers
```

> **Note:** Some fixers may incur additional costs (e.g., enabling certain cloud services like `Access Analyzer`, `GuardDuty`, and `SecurityHub` in AWS).

---

## Fixer Class Structure

### Base Class

All fixers inherit from the abstract `Fixer` class (`prowler/lib/fix/fixer.py`). This class defines the required interface and common logic.

**Key methods and properties:**
- `__init__(description, cost_impact=False, cost_description=None)`: Sets metadata for the fixer.
- `_get_fixer_info()`: Returns a dictionary with fixer metadata.
- `fix(finding=None, **kwargs)`: Abstract method. Must be implemented by each fixer to perform the remediation.
- `get_fixer_for_finding(finding)`: Factory method to dynamically load the correct fixer for a finding.
- `run_fixer(findings)`: Runs the fixer(s) for one or more findings.

### Provider-Specific Base Classes

Each provider extends the base class to add provider-specific logic and metadata:

- **AWS:** `AWSFixer` (`prowler/providers/aws/lib/fix/fixer.py`)
- **Azure:** `AzureFixer` (`prowler/providers/azure/lib/fix/fixer.py`)
- **GCP:** `GCPFixer` (`prowler/providers/gcp/lib/fix/fixer.py`)
- **M365:** `M365Fixer` (`prowler/providers/m365/lib/fix/fixer.py`)

These classes may add fields such as required permissions, IAM policies, or provider-specific client handling.

---

## Writing a Fixer

### 1. **Location and Naming**

- Place your fixer in the check’s directory, named `<check_id>_fixer.py`.
- The fixer class should be named in PascalCase, matching the check ID, ending with `Fixer`.
  Example: For `ec2_ebs_default_encryption`, use `Ec2EbsDefaultEncryptionFixer`.

### 2. **Class Definition**

- Inherit from the provider’s base fixer class.
- Implement the `fix()` method. This method receives a finding and/or keyword arguments and must return `True` if the remediation was successful, `False` otherwise.

**Example (AWS):**
```python
from prowler.providers.aws.lib.fix.fixer import AWSFixer

class Ec2EbsDefaultEncryptionFixer(AWSFixer):
    def __init__(self):
        super().__init__(
            description="Enable EBS encryption by default in a region.",
            service="ec2",
            iam_policy_required={
                "Action": ["ec2:EnableEbsEncryptionByDefault"],
                "Resource": "*"
            }
        )

    def fix(self, finding=None, **kwargs):
        # Remediation logic here
        return True
```

**Example (Azure):**
```python
from prowler.providers.azure.lib.fix.fixer import AzureFixer

class AppFunctionFtpsDeploymentDisabledFixer(AzureFixer):
    def __init__(self):
        super().__init__(
            description="Disable FTP/FTPS deployments for Azure Functions.",
            service="app",
            permissions_required={
                "actions": [
                    "Microsoft.Web/sites/write",
                    "Microsoft.Web/sites/config/write"
                ]
            }
        )

    def fix(self, finding=None, **kwargs):
        # Remediation logic here
        return True
```

**Example (GCP):**
```python
from prowler.providers.gcp.lib.fix.fixer import GCPFixer

class ComputeInstancePublicIPFixer(GCPFixer):
    def __init__(self):
        super().__init__(
            description="Remove public IP from Compute Engine instance.",
            service="compute",
            iam_policy_required={
                "roles": ["roles/compute.instanceAdmin.v1"]
            }
        )

    def fix(self, finding=None, **kwargs):
        # Remediation logic here
        return True
```

**Example (M365):**
```python
from prowler.providers.m365.lib.fix.fixer import M365Fixer

class AppFunctionFtpsDeploymentDisabledFixer(M365Fixer):
    def __init__(self):
        super().__init__(
            description="Disable FTP/FTPS deployments for Azure Functions.",
            service="app",
            permissions_required={
                "actions": [
                    "Microsoft.Web/sites/write",
                    "Microsoft.Web/sites/config/write"
                ]
            }
        )

    def fix(self, finding=None, **kwargs):
        # Remediation logic here
        return True
```
---

## Fixer info

Each fixer should provide:

- **description:** What the fixer does.
- **cost_impact:** Whether the remediation may incur costs.
- **cost_description:** Details about potential costs (if any).

For some providers, there will be additional information that needs to be added to the fixer info, like:

- **service:** The cloud service affected.
- **permissions/IAM policy required:** The minimum permissions needed for the fixer to work.

In order to get the fixer info, you can use the flag `--fixer-info`. And it will print the fixer info in a pretty format.

---

## Fixer Config File

Some fixers support configurable parameters.
You can use the default config file at `prowler/config/fixer_config.yaml` or provide your own with `--fixer-config`.

**Example YAML:**
```yaml
aws:
  ec2_ebs_default_encryption: {}
  iam_password_policy:
    MinimumPasswordLength: 14
    RequireSymbols: True
    # ...
azure:
  app_function_ftps_deployment_disabled:
    ftps_state: "Disabled"
```

---

## Best Practices

- Always document the permissions required for your fixer.
- Handle exceptions gracefully and log errors.
- Return `True` only if the remediation was actually successful.
- Use the provider’s client libraries and follow their best practices for API calls.

---

## Troubleshooting

- If a fixer is not available for a check, Prowler will print a warning.
- If a fixer fails due to missing permissions, check the required IAM roles or permissions and update your execution identity accordingly.
- Use the `--list-fixers` flag to see all available fixers for your provider.

---

## Extending to New Providers

To add support for a new provider:

1. Implement a new base fixer class inheriting from `Fixer`.
2. Place it in the appropriate provider directory.
3. Follow the same structure for check-specific fixers.

---

**For more details, see the code in `prowler/lib/fix/fixer.py` and the provider-specific fixer base classes.**
