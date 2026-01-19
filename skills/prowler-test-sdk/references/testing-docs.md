# SDK Testing Documentation

## Local Documentation

For detailed SDK testing patterns, see:

- `docs/developer-guide/unit-testing.mdx` - Complete guide for writing check tests

## Contents

The documentation covers:
- AWS testing with moto (`@mock_aws` decorator)
- Azure testing with MagicMock
- GCP testing with MagicMock
- Provider-specific fixtures (`set_mocked_aws_provider`, etc.)
- Service dependency table for CI optimization
- Test structure and required scenarios
