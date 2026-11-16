# SDK Testing Documentation

## Local Documentation

- `docs/developer-guide/unit-testing.mdx` - Full SDK testing guide: moto vs `mock_make_api_call` vs MagicMock, patching vs importing, AWS service dependency table, GCP/Azure/K8s/M365 patterns
- `docs/developer-guide/test-impact-analysis.mdx` - How CI selects which tests to run for a PR

## Source of Truth in Code

- `tests/providers/aws/utils.py` - `set_mocked_aws_provider`, `mocked_api_response`, AWS constants
- `tests/providers/{provider}/{provider}_fixtures.py` - `set_mocked_{provider}_provider` and constants
- `tests/conftest.py` - Autouse fixture that resets attributes set on mock classes
- `.github/workflows/sdk-tests.yml` - Per-provider test jobs and the AWS `dependents` table
