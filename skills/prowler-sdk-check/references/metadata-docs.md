# Check Documentation

## Local Documentation

- `docs/developer-guide/checks.mdx` - Check structure, statuses, resource identification, metadata fields
- `docs/developer-guide/check-metadata-guidelines.mdx` - Writing rules for CheckTitle, Description, Risk, Remediation, Categories
- `docs/developer-guide/configurable-checks.mdx` - `audit_config`, `config.yaml` and the provider config schemas
- `docs/developer-guide/renaming-checks.mdx` - Renaming existing checks (CheckAliases)
- `docs/developer-guide/secret-scanning-checks.mdx` - Batched structure for checks that scan for plaintext secrets
- `docs/developer-guide/<provider>-details.mdx` - Provider-specific check patterns

## Source of Truth in Code

- `prowler/lib/check/models.py` - `CheckMetadata` validators, `VALID_CATEGORIES`, `VALID_RESOURCE_GROUPS`, `Check`, report classes
- `prowler/providers/aws/config/check_types.json` - Valid AWS `CheckType` paths
- `prowler/lib/check/check.py` - `run_fixer`, external check loading
- `prowler/config/config.yaml`, `prowler/config/schema/` - Configurable check defaults and their schemas
