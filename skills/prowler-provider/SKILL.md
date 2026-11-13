---
name: prowler-provider
description: >
  Creates new Prowler providers (built-in or external plug-in) or adds services to existing providers.
  Trigger: When adding a new provider to the Prowler SDK, building an external provider plug-in (prowler.providers entry point), implementing the Provider contract (from_cli_args, get_scan_arguments, get_credentials_schema), or adding a new service to an existing provider.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, sdk]
  auto_invoke:
    - "Adding new providers"
    - "Adding services to existing providers"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

- Adding a built-in provider under `prowler/providers/`
- Shipping a provider, checks or compliance frameworks as an external package (entry points)
- Adding a service (`{service}_service.py` + `{service}_client.py`) to an existing provider

Choose the provider type first (`docs/developer-guide/provider.mdx`): **SDK** (official Python SDK, e.g. AWS, Azure, GCP, Kubernetes), **API** (direct REST calls, e.g. NHN, MongoDB Atlas), **Hybrid** (e.g. M365, GitHub), or **Tool/Wrapper** (delegates to an external tool: `iac`, `image`, `llm`).

## Provider Layout

```text
prowler/providers/{provider}/
├── __init__.py
├── {provider}_provider.py          # class {Provider}Provider(Provider)
├── models.py                       # identity/session models, {Provider}OutputOptions
├── {provider}_regions_by_service.json  # regional providers only
├── exceptions/exceptions.py        # provider-specific exception codes
├── lib/
│   ├── arguments/arguments.py      # init_parser(self), optional validate_arguments(), SENSITIVE_ARGUMENTS
│   ├── mutelist/mutelist.py        # {Provider}Mutelist(Mutelist).is_finding_muted()
│   └── service/service.py          # base service class
└── services/{service}/
    ├── {service}_service.py
    ├── {service}_client.py
    └── {check_name}/               # see prowler-sdk-check
```

## Critical Rules

- **Class name**: `Provider.get_class()` imports `prowler.providers.{name}.{name}_provider` and expects `f"{name.capitalize()}Provider"`: `stackit` -> `StackitProvider`, `alibabacloud` -> `AlibabacloudProvider`, `mongodbatlas` -> `MongodbatlasProvider`. Any other casing fails to load.
- **Abstract members** of `prowler/providers/common/provider.py` `Provider`: properties `type`, `identity`, `session`, `audit_config`; methods `setup_session()`, `print_credentials()`. Also implement `test_connection()` (the API uses it), `fixer_config` and `mutelist` properties.
- `Provider` has no `__init__` contract: the subclass `__init__` takes explicit kwargs (credentials, `config_path`, `config_content`, `fixer_config`, `mutelist_path`, `mutelist_content`, scoping) and **must end with `Provider.set_global_provider(self)`**.
- `sdk_only = True` by default (CLI only). Set `sdk_only = False` only when the API/UI support the provider (`Provider.get_app_providers()`).
- Tool wrappers set `is_external_tool_provider = True` (external) or are listed in `EXTERNAL_TOOL_PROVIDERS` (`prowler/lib/check/external_tool_providers.py`, built-in); they skip check loading and most metadata validation.
- Secret-bearing flags: `nargs="?"`, `default=None`, env var preferred, and listed in the module-level `SENSITIVE_ARGUMENTS` frozenset in `lib/arguments/arguments.py` (collected by `prowler/lib/cli/redact.py` to redact output). Do not add new flags that require passing secrets on the command line.
- Services never raise on API errors: log and keep a distinguishable "not retrieved" state (see `prowler-sdk-check`, permission errors are not findings).
- Resource models can declare `sensitive_fields: ClassVar[tuple[str, ...]] = ("field",)` so `Check_Report` redacts those values in outputs.

## Service and Client

```python
# prowler/providers/{provider}/services/{service}/{service}_client.py
from prowler.providers.common.provider import Provider
from prowler.providers.{provider}.services.{service}.{service}_service import {Service}

{service}_client = {Service}(Provider.get_global_provider())
```

The client is a module-level singleton created on first import; the service fetches everything in `__init__` and checks only read attributes. A service may read another service's client, but never instantiate another provider SDK client for it. Templates: [assets/service.py](assets/service.py), [assets/client.py](assets/client.py).

## Built-in Provider: Files to Touch

Verified against `stackit` and `alibabacloud`; grep an existing provider name across `prowler/` and `tests/` to catch anything new.

| File | Change |
|------|--------|
| `prowler/providers/{provider}/` | Provider package (layout above) |
| `prowler/providers/common/provider.py` | `elif arguments.provider == "{provider}":` branch in `init_global_provider` mapping CLI args to the constructor (exact equality, not substring) |
| `prowler/lib/cli/parser.py` | Add to `known_providers`, the `usage=` string and the epilog provider list |
| `prowler/__main__.py` | Import and build `{Provider}OutputOptions`; compliance output branch if the provider ships frameworks |
| `prowler/config/config.py` | `Provider` enum value |
| `prowler/config/config.yaml` + `prowler/config/schema/{provider}.py` + `registry.py` | Only if the provider has configurable checks |
| `prowler/config/{provider}_mutelist_example.yaml` | Example mutelist |
| `prowler/lib/check/models.py` | `CheckReport{Provider}(Check_Report)` dataclass |
| `prowler/lib/outputs/finding.py` | Provider branches filling `auth_method`, `account_uid`, `account_name`, `resource_uid`, `region`, ... |
| `prowler/lib/outputs/outputs.py` | `stdout_report` detail field |
| `prowler/lib/outputs/summary_table.py` | Entity type and audited entities |
| `prowler/lib/outputs/html/html.py` | `get_{provider}_assessment_summary()` |
| `prowler/compliance/{provider}/__init__.py` | When the provider ships compliance frameworks (`prowler-compliance` skill) |
| `pyproject.toml` (+ `uv lock`) | Pinned SDK dependencies (exact versions, e.g. `stackit-core==0.2.0`) |
| `tests/providers/{provider}/` | `{provider}_fixtures.py` (`set_mocked_{provider}_provider`), provider, arguments, mutelist, service and check tests |
| `tests/lib/check/check_test.py` | `test_{provider}_checks_metadata_is_valid` |
| `tests/lib/cli/parser_test.py`, `tests/lib/outputs/*_test.py` | Usage string and output branches |
| `.github/workflows/sdk-tests.yml`, `.github/labeler.yml` | Per-provider test job and PR label |
| `docs/developer-guide/{provider}-details.mdx`, `docs/user-guide/providers/{provider}/` | Docs (`prowler-docs` skill); provider cards regenerate via the `generate-provider-cards` prek hook |
| `README.md` | Provider table (`prowler-readme-table` skill) |
| `prowler/changelog.d/{slug}.added.md` | Changelog fragment (`prowler-changelog` skill) |

API/UI integration (ProviderChoices, serializers, migrations, credential forms) is a separate step: `docs/developer-guide/provider.mdx` Step 2/3 and the `prowler-api` / `prowler-ui` skills.

## External Provider Plug-in (entry points)

A separate package can add a provider without touching the repo. Discovery is in `Provider.get_available_providers()` / `Provider.get_class()`:

```toml
# plug-in pyproject.toml
[project.entry-points."prowler.providers"]
myprov = "prowler_myprov.myprov_provider:MyprovProvider"      # must subclass Provider

[project.entry-points."prowler.checks.myprov"]
myservice_resource_enabled = "prowler_myprov.services.myservice.myservice_resource_enabled.myservice_resource_enabled"

[project.entry-points."prowler.compliance"]
myprov = "prowler_myprov.compliance"                            # package dir holding framework JSONs

[project.entry-points."prowler.compliance.universal"]
myprov = "prowler_myprov.universal_compliance"                  # universal-format frameworks
```

- A built-in with the same name always wins; the plug-in is ignored with a warning.
- No `elif` branches exist for plug-ins, so the dynamic contract methods replace them:

| Method | Used by |
|--------|---------|
| `init_parser(parser)` (class attribute) and `_cli_help_text` | CLI subparser and help (`prowler/providers/common/arguments.py`, `parser.py`) |
| `from_cli_args(arguments, fixer_config)` classmethod | `init_global_provider`; return the instance or call `set_global_provider` in `__init__` |
| `get_output_options(arguments, bulk_checks_metadata)` | `__main__.py`; falls back to `default_output_options` if not implemented |
| `get_stdout_detail(finding)`, `get_finding_sort_key()` | `prowler/lib/outputs/outputs.py` |
| `get_finding_output_data(check_output)` | `prowler/lib/outputs/finding.py` |
| `get_summary_entity()` | `summary_table.py` (default: `(type, identity.account_id)`) |
| `get_html_assessment_summary()` | `html.py` |
| `generate_compliance_output(...)`, `display_compliance_table(...)` | Compliance CSV and terminal table |
| `get_mutelist_finding_args()` | `prowler/lib/check/check.py` (kwargs for `mutelist.is_finding_muted`) |
| `get_scan_arguments(provider_uid, secret, mutelist_content)` | Programmatic construction from a stored uid + secret (intended for the API). Base passes `secret` through, adds `mutelist_content`, drops `provider_uid`: override when the uid is part of the scan scope |
| `get_connection_arguments(provider_uid, secret)` | kwargs for `test_connection`; same override rule |
| `get_credentials_schema()` | `{"static" \| "role" \| "service_account": PydanticModel}` documenting each field with `Field(description=...)`; `{}` means "validated only by `test_connection`" |

Reference implementation used by the tests: `tests/providers/external/test_dynamic_provider_loading.py`.

## Commands

```bash
uv run python prowler-cli.py {provider} --help
uv run python prowler-cli.py {provider} --list-services
uv run python prowler-cli.py {provider} --list-checks
uv run python prowler-cli.py {provider} --service {service} --log-level DEBUG
uv run pytest -n auto tests/providers/{provider}/
uv run pytest tests/lib/cli/parser_test.py tests/lib/outputs/ tests/providers/external/
```

## Resources

- **Templates**: [assets/](assets/) for Provider, Service and client singleton templates (based on GitHub)
- **Documentation**: [references/provider-docs.md](references/provider-docs.md)
