# Configurable Checks in Prowler

Prowler empowers users to extend and adapt cloud security coverage by making checks configurable through the use of the `audit_config` object. This allows checks to be tailored to specific requirements via a configuration file.

## What Is `audit_config`?

The `audit_config` object is a dictionary attached to each provider's service client (e.g., `<service_name>_client.audit_config`). This object loads configuration values from the main configuration file (`prowler/config/config.yaml`). Use `audit_config` to make checks flexible and user-configurable.

## How to Use `audit_config` in a Check

To retrieve configuration values in your check code, use the `.get()` method on the `audit_config` object. For example, to get the minimum number of Availability Zones for Lambda from the configuration file, use the following code. If the value is not set in the configuration, the check will default to 2:

```python
LAMBDA_MIN_AZS = awslambda_client.audit_config.get("lambda_min_azs", 2)
```

Always provide a default value in `.get()` to ensure the check works even if the configuration is missing the variable.

### Example: Security Group Rule Limit

```python title="ec2_securitygroup_with_many_ingress_egress_rules.py"
class ec2_securitygroup_with_many_ingress_egress_rules(Check):
    def execute(self):
        findings = []
        max_security_group_rules = ec2_client.audit_config.get(
            "max_security_group_rules", 50
        )
        for security_group_arn, security_group in ec2_client.security_groups.items():
            # ... check logic ...
```

## Files to Update When Adding a Configurable Variable

If you want to add a new check to Prowler ensure to add the configurable variable to the following files:

- **prowler/config/config.yaml**
  Add the new configuration variable under the relevant provider or service section.
  Example:
  ```yaml
  # aws.awslambda_function_vpc_multi_az
  lambda_min_azs: 2
  ```
- **tests/config/fixtures/config.yaml**
  Add the variable if tests depend on this configuration.
- **docs/tutorials/configuration_file.md**
  Document the new variable in the list of configurable checks.

For a complete list of checks that already support configuration, see the [Configuration File tutorial](../tutorials/configuration_file.md).

This approach ensures that both checks can be easily configured by users, making Prowler highly adaptable to different environments and requirements.
