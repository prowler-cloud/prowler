# Provider Documentation

## Local Documentation

### Core Documentation
- `docs/developer-guide/provider.mdx` - Provider types, step-by-step CLI, API and UI integration, OCSF requirements, checklist
- `docs/developer-guide/services.mdx` - Adding services, cross-service communication, regional services
- `docs/developer-guide/configurable-checks.mdx` - Provider config schemas in `prowler/config/schema/`

### Provider-Specific Details
- `docs/developer-guide/{aws,azure,gcp,kubernetes,github,m365,alibabacloud,stackit,llm}-details.mdx`

## Source of Truth in Code

- `prowler/providers/common/provider.py` - `Provider` ABC, dynamic contract methods, `init_global_provider`, `get_class`, entry-point loading
- `prowler/providers/common/arguments.py` - Provider subparser loading (built-in and plug-in)
- `prowler/providers/common/builtin.py`, `prowler/lib/check/tool_wrapper.py` - Built-in and tool-wrapper detection
- `prowler/lib/check/utils.py`, `prowler/lib/check/check.py` - `prowler.checks.{provider}` discovery
- `prowler/lib/check/compliance_models.py`, `prowler/config/config.py` - `prowler.compliance` and `prowler.compliance.universal` discovery
- `tests/providers/external/test_dynamic_provider_loading.py` - Fake external provider used in tests

Note: `provider.mdx` Step 11 still shows a substring match (`"your_provider" in provider_class_name.lower()`); the code now dispatches by exact name (`arguments.provider == "..."`).
