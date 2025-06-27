# Creating Custom Checks in Prowler

Prowler empowers users to extend cloud security coverage by creating custom checks tailored to specific requirements. This guide explains how to use the `audit_config` object to make checks configurable and highlights the files to update when introducing new configuration options.

## What Is `audit_config`?

The `audit_config` object is a dictionary attached to each provider's service client (`<service_name>_client.audit_config`). This object loads configuration values from the main configuration file (`prowler/config/config.yaml`). Use `audit_config` to make checks flexible and user-configurable.

## How to Use `audit_config` in a Check

To retrieve configuration values in your check code, use the `.get()` method on the `audit_config` object. For example, to get the minimum number of Availability Zones for Lambda from the configuration file, use the following code. If the value is not set in the configuration, the check will default to 2:

```python
LAMBDA_MIN_AZS = awslambda_client.audit_config.get("lambda_min_azs", 2)
```

Always provide a default value in `.get()` to ensure the check works even if the configuration is missing the variable.

## Files to Update When Adding a Configurable Variable

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
