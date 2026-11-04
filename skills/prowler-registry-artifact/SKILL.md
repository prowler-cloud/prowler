---
name: prowler-registry-artifact
description: >
  Packages Prowler checks, compliance frameworks (legacy and universal) and providers as external
  plug-in Python wheels discovered through entry points, and publishes them on the Prowler Registry.
  Trigger: When creating a pyproject.toml with prowler.checks.*, prowler.providers, prowler.compliance or
  prowler.compliance.universal entry points, building or testing a plug-in wheel, or uploading/installing
  artifacts with registry.prowler.com.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
  scope: [root, sdk]
  auto_invoke:
    - "Packaging checks, compliance frameworks or providers as external packages"
    - "Publishing artifacts to Prowler Registry"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

- Shipping checks, compliance JSON or a whole provider OUTSIDE the Prowler repo, installable with `pip`/`uv`
- Publishing those wheels (public or private) on the Prowler Registry
- Debugging "my plug-in check/framework/provider does not show up"

Writing the check, provider or framework itself: use `prowler-sdk-check`, `prowler-provider`, `prowler-compliance`.
This skill covers only packaging, discovery and publishing.

---

## Entry-Point Groups (source of truth: the loaders)

| Group | Entry-point name | Entry-point value | Loader |
|---|---|---|---|
| `prowler.checks.{provider}` | CheckID | Check module path `{pkg}.services.{service}.{check_id}.{check_id}` | `prowler/lib/check/utils.py` (`_recover_ep_checks`), `prowler/lib/check/check.py` (`_resolve_check_module`) |
| `prowler.providers` | Provider name used on the CLI | `module:Class` of a `Provider` subclass (`ep.load()`) | `prowler/providers/common/provider.py`, `prowler/lib/check/tool_wrapper.py` |
| `prowler.compliance` | Provider the JSON files belong to (`aws`, `azure`, ...) | Package whose directory holds the JSON files | `prowler/config/config.py` (`_get_ep_compliance_dirs`), `prowler/lib/check/compliance_models.py` |
| `prowler.compliance.universal` | Free-form (only the value is used) | Package whose directory holds universal JSON files | `prowler/lib/check/compliance_models.py` (`get_universal_compliance_entry_point_dirs`) |

---

## Critical Rules

| Rule | Why (code) |
|---|---|
| Check value MUST contain `.services.{service}.` | `_recover_ep_checks` skips entry points without it when `--services` is used |
| Class name == CheckID == module file name | Execution does `getattr(lib, check_name)` |
| CheckID prefix (before first `_`) == service | `service = check_name.split("_")[0]` in `check.py` |
| `{check_id}.metadata.json` ships in the wheel next to the module | `CheckMetadata.get_bulk()` reads `{check_path}/{check_name}.metadata.json` |
| Keep package `__init__.py` files empty | Discovery uses `find_spec` (no import) to avoid initializing service clients |
| IDs must be unique vs built-ins | Built-in ALWAYS wins: check metadata, provider name and framework name collisions are ignored (checks/providers log "is being IGNORED") |
| Compliance framework key = JSON file name without `.json` | `framework_version_provider` naming, e.g. `acme_baseline_1.0_aws.json` |
| External legacy compliance JSON that fails to parse is skipped with a warning | Loaded with `fatal=False`; always confirm with `--list-compliance` |
| Universal JSON is offered to every provider present in a requirement's `checks` keys | `supports_provider()` |
| Quote dotted group names in TOML | `[project.entry-points."prowler.checks.aws"]` |
| Require `prowler>=5.37.1` for checks on built-in providers | Before 5.37.1 (#12312) such checks were listed but silently produced no findings |

### Provider Plug-in Contract

Subclass `prowler.providers.common.provider.Provider`. Minimal working example:
`FakeExternalProvider` in `tests/providers/external/test_dynamic_provider_loading.py`.

| Member | Purpose |
|---|---|
| `init_parser(cls, parser)` classmethod | Adds the `prowler {provider}` subcommand |
| `from_cli_args(cls, arguments, fixer_config)` | Builds the provider for any non-built-in name |
| `_cli_help_text` | Text in `prowler --help` |
| `sdk_only` (default `True`) | Set `False` so the API/UI list it (`get_app_providers()`) |
| `get_scan_arguments`, `get_connection_arguments`, `get_credentials_schema` | Build/validate from stored uid + secret dict |
| `is_external_tool_provider` (default `False`) | `True` for tool wrappers: check loading is bypassed |

---

## Package Layouts

Templates with full `pyproject.toml`: [assets/](assets/). Hatchling (Prowler's own backend) includes every
file under the listed package, so the JSON files are packaged automatically.

```text
# Checks-only (assets/pyproject-checks.toml)
src/{pkg}/__init__.py
src/{pkg}/services/__init__.py
src/{pkg}/services/{service}/__init__.py
src/{pkg}/services/{service}/{check_id}/__init__.py
src/{pkg}/services/{service}/{check_id}/{check_id}.py
src/{pkg}/services/{service}/{check_id}/{check_id}.metadata.json

# Compliance (assets/pyproject-compliance.toml)
src/{pkg}/{provider}/__init__.py + {framework}_{version}_{provider}.json
src/{pkg}/universal/__init__.py  + {framework}_{version}.json

# Provider (assets/pyproject-provider.toml)
src/{pkg}/provider.py            # class {Name}Provider(Provider)
src/{pkg}/services/{service}/{service}_service.py, {service}_client.py, {check_id}/...
src/{pkg}/compliance/__init__.py + {framework}_{version}_{provider}.json
```

Minimal entry points:

```toml
[project.optional-dependencies]
runtime = ["prowler>=5.48.0"]   # Registry installs use "<package-name>[runtime]"

[project.entry-points."prowler.checks.aws"]
s3_bucket_owner_tag_present = "acme_prowler_checks.services.s3.s3_bucket_owner_tag_present.s3_bucket_owner_tag_present"

[project.entry-points."prowler.providers"]
acme = "prowler_acme.provider:AcmeProvider"

[project.entry-points."prowler.compliance"]
aws = "acme_prowler_compliance.aws"

[project.entry-points."prowler.compliance.universal"]
acme = "acme_prowler_compliance.universal"
```

Naming: Registry package names follow PEP 503 normalization (lowercase; `-`, `.`, `_` folded to `-`).
Check metadata must pass the same validators as built-ins (see `prowler-sdk-check`).

---

## Build, Install, Verify (local)

```bash
uv build --wheel                                   # Registry accepts only .whl
# {dist} = project name with "-" -> "_" (e.g. acme_prowler_checks), not the import package
unzip -l dist/{dist}-0.1.0-py3-none-any.whl        # metadata/compliance JSON present?
unzip -p dist/{dist}-0.1.0-py3-none-any.whl '{dist}-0.1.0.dist-info/entry_points.txt'

python3.12 -m venv /tmp/plugin-venv && source /tmp/plugin-venv/bin/activate
pip install "./dist/{dist}-0.1.0-py3-none-any.whl[runtime]"

python -c "import importlib.metadata as m; print(m.entry_points(group='prowler.checks.aws'))"
prowler aws --list-checks | grep {check_id}
prowler aws --list-checks --services {service} | grep {check_id}
prowler aws --list-checks --log-level WARNING      # surfaces "is being IGNORED" collisions
prowler aws --list-compliance | grep {framework}
prowler aws --list-compliance-requirements {framework}_{version}_aws
prowler {provider} --list-checks                   # external provider subcommand exists
prowler aws --checks {check_id}                    # real run (needs credentials)
```

Inside a Prowler checkout, without touching its venv:
`uv run --frozen --with ./dist/{dist}-0.1.0-py3-none-any.whl python prowler-cli.py aws --list-checks`.
Provider contract tests:
`uv run pytest tests/providers/external/test_dynamic_provider_loading.py -q`.

---

## Publish to the Prowler Registry

Requires an organization API key with upload scope (`upload:public` or `upload:private`).
Keys start with `prr_`; auth is HTTP Basic with user `__token__` and the key as password. Never hardcode keys.

```bash
uvx twine check dist/*.whl

# twine
twine upload --repository-url https://registry.prowler.com/simple/ \
  -u __token__ -p "$PRR_UPLOAD_KEY" dist/*.whl

# uv
uv publish --publish-url https://registry.prowler.com/simple/ \
  --token "$PRR_UPLOAD_KEY" dist/*.whl
```

Use `dist/*.whl`, not `dist/*`: `.tar.gz` and other formats are rejected with `400`.

### Processing statuses

| Status | Meaning |
|---|---|
| `pending` | Stored; worker extracts PEP 658 metadata and validates artifact scaffolding and metadata in the wheel |
| `processed` | Valid; checks become visible |
| `invalid` | Rejected; read `rejection_reason` |

| Situation | Result |
|---|---|
| Package references a provider unknown to the Registry | Provider auto-created as pending; package rejected until the registry owner accepts it, then re-upload |
| Re-upload of a rejected version | Allowed; replaces the rejected version |
| Re-upload of a `processed` version | `409 Conflict`: bump `version` |

The only documented rejection cause is the pending provider; the Registry otherwise says it validates "artifact
scaffolding and metadata". Always read `rejection_reason`. Before uploading, rule out locally what would also break
Prowler: JSON files missing from the wheel, entry-point values pointing to modules not in the wheel, and check
metadata that fails validation (`prowler {provider} --list-checks` in a clean venv exercises all three).

### Install from the Registry

```bash
# Public
pip install --extra-index-url https://registry.prowler.com/simple/ "<package-name>[runtime]"
# Private (download key: download:official | download:official-verified | download:all).
# Resolve the artifact ONLY from the Registry: --extra-index-url would also search PyPI, where a public package
# with the same name could win (dependency confusion). Install runtime dependencies from PyPI separately.
pip install --index-url https://__token__:${PRR_DOWNLOAD_KEY}@registry.prowler.com/simple/ --no-deps "<package-name>==1.2.0"
pip install "prowler>=5.48.0"
# Pin like any package
pip install --extra-index-url https://registry.prowler.com/simple/ "<package-name>[runtime]==1.2.0"
```

Installed artifacts are discovered automatically: `prowler aws --checks {check_id}`.
Bundles (curated sets of private packages, Draft -> Deployed -> Archived) and verified packages are managed in
the Registry web UI (Settings > Bundles, Settings > API Keys).

---

## Checklist

- [ ] CheckIDs, provider name and framework file names do not collide with built-ins
- [ ] Every check: `.services.{service}.` in value, class == CheckID, metadata JSON beside module
- [ ] `__init__.py` at every package level, all empty
- [ ] Dotted entry-point groups quoted in `pyproject.toml`
- [ ] `runtime` extra pulls `prowler` (>=5.37.1 if adding checks to built-in providers)
- [ ] `uv build --wheel`; `unzip -l` shows JSON files; `entry_points.txt` has the right groups
- [ ] Clean venv install + `--list-checks` / `--list-compliance` show the content, no IGNORED warnings
- [ ] `twine check` passes; version bumped if already `processed`
- [ ] Upload with a key from env/secret store; wait for `processed`, otherwise fix `rejection_reason`

## Resources

- **Templates**: [assets/](assets/) - `pyproject.toml` for checks, compliance and provider artifacts
- **Loaders**: `prowler/lib/check/utils.py`, `prowler/lib/check/check.py`, `prowler/lib/check/models.py`,
  `prowler/providers/common/provider.py`, `prowler/config/config.py`, `prowler/lib/check/compliance_models.py`
- **Provider example**: `tests/providers/external/test_dynamic_provider_loading.py`
- **Related skills**: `prowler-sdk-check`, `prowler-provider`, `prowler-compliance`
