# Workflow A: Sync a Framework With an Upstream Catalog

Use when a framework is maintained upstream (CIS Benchmarks, FINOS CCC, CSA CCM, NIST, ENS, etc.) and
Prowler needs to catch up. The bundled runner writes **legacy per-provider** JSONs and validates them with
`Compliance.parse_file()`; for universal files, adapt the output or edit the JSON directly.

## Step 1: Cache the upstream source

Download every upstream file once so iterations do not hit the network. FINOS CCC example:

```bash
mkdir -p /tmp/ccc_upstream
catalogs="core/ccc storage/object management/auditlog management/logging ..."
for p in $catalogs; do
  safe=$(echo "$p" | tr '/' '_')
  gh api "repos/finos/common-cloud-controls/contents/catalogs/$p/controls.yaml" \
    -H "Accept: application/vnd.github.raw" > "/tmp/ccc_upstream/${safe}.yaml"
done
```

## Step 2: Run the config-driven runner

```text
assets/
├── sync_framework.py      # generic runner
├── configs/ccc.yaml       # per-framework config (canonical example)
└── parsers/finos_ccc.py   # parser for FINOS CCC YAML
```

```bash
python skills/prowler-compliance/assets/sync_framework.py \
       skills/prowler-compliance/assets/configs/ccc.yaml
```

The runner loads the config, imports `parsers.<parser.module>`, calls `parse_upstream(config) -> list[dict]`,
then: asserts id uniqueness (raises, never renumbers), normalizes `FamilyName`, preserves existing `Checks`
by primary key plus fallback keys, writes one JSON per provider and re-validates it.

### Adding a framework to the runner

1. `assets/configs/{framework}.yaml` (copy `ccc.yaml`):
   - `framework`: `name`, `display_name`, `version` (required and non-empty, the runner refuses to start
     otherwise), `description_template`.
   - `providers`: list of `{key, display}`.
   - `output.path_template`: e.g. `"prowler/compliance/{provider}/cis_{version}_{provider}.json"`
     (placeholders `{provider}`, `{framework}`, `{version}`).
   - `upstream.dir`: the Step 1 cache.
   - `parser.module`: module under `parsers/`; the rest of `parser.` is passed through.
   - `post_processing.check_preservation.primary_key` (usually `Id`) and `fallback_keys` (tuples of
     `Attributes[0]` fields: CCC `[Section, Applicability]`, CIS `[Section, Profile]`, NIST `[ItemId]`).
     For a version bump that writes a new file, set `legacy_path_template` to the previous version's
     file or its mappings are lost.
   - `post_processing.family_name_normalization` (optional): raw → canonical map; the UI groups by exact
     value.
2. Reuse a parser or write `parsers/{name}.py` with `parse_upstream(config) -> list[dict]` returning
   Prowler-format requirements with unique ids. The parser owns upstream quirks.

### Upstream quirks seen in the FINOS CCC sync

- Multiple YAML shapes: most catalogs use `control-families: [...]`, `storage/object` uses top-level
  `controls: [...]`. A single-shape parser silently drops whole catalogs. Test one file of each shape.
- Block scalars keep newlines; Prowler stores single-line text: `" ".join(value.split())`.
- Foreign-prefix ids (`CCC.AuditLog.CN08.AR01` nested under `CCC.Logging.CN03`) must be rewritten to the
  parent (`CCC.Logging.CN03.AR01`).
- Genuine upstream collisions (two requirements, one id): renumber the second to the next free number;
  fallback keys recover its mappings.

## Step 3: Validate

Run the Validation section of `SKILL.md` (loader, catalog integrity test, CLI smoke test).

## Step 4: Attribute model (legacy only, rare)

Only when the framework must stay legacy and needs fields beyond `Generic_Compliance_Requirement_Attribute`:
add a class to `compliance_models.py` and register it in `Compliance_Requirement.Attributes` before
Generic. For new frameworks use universal `attributes_metadata` instead.
