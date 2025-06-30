# Configurable Checks in Prowler

Prowler empowers users to extend and adapt cloud security coverage by making checks configurable through the use of the `audit_config` object. This approach enables customization of checks to meet specific requirements through a configuration file.

## Understanding the `audit_config` Object

The `audit_config` object is a dictionary attached to each provider's service client (for example, `<service_name>_client.audit_config`). This object loads configuration values from the main configuration file (`prowler/config/config.yaml`). Use `audit_config` to make checks flexible and user-configurable.

## Using `audit_config` to Configure Checks

Retrieve configuration values in a check by using the `.get()` method on the `audit_config` object. For example, to get the minimum number of Availability Zones for Lambda from the configuration file, use the following code. If the value is not set in the configuration, the check defaults to 2:

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

## Required File Updates for Configurable Variables

When adding a new configurable check to Prowler, update the following files:

- **Configuration File:** Add the new variable under the relevant provider or service section in `prowler/config/config.yaml`.
  ```yaml
  # aws.awslambda_function_vpc_multi_az
  lambda_min_azs: 2
  ```
- **Test Fixtures:** If tests depend on this configuration, add the variable to `tests/config/fixtures/config.yaml`.
- **Documentation:** Document the new variable in the list of configurable checks in `docs/tutorials/configuration_file.md`.

For a complete list of checks that already support configuration, see the [Configuration File Tutorial](../tutorials/configuration_file.md).

This approach ensures that checks are easily configurable, making Prowler highly adaptable to different environments and requirements.
