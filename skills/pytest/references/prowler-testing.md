# Prowler-Specific Testing Patterns

## Local Documentation

For Prowler-specific pytest patterns, see:

- `docs/developer-guide/unit-testing.mdx` - Complete SDK testing guide

## Contents

The Prowler documentation covers patterns NOT in the generic pytest skill:
- `set_mocked_aws_provider()` fixture pattern
- `@mock_aws` decorator usage with moto
- `mock_make_api_call` pattern
- Service dependency table for CI optimization
- Provider-specific mocking (AWS: moto, plus botocore `_make_api_call` patching or MagicMock when moto lacks the API; other providers: MagicMock)
