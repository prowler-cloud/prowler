#!/usr/bin/env python3
"""
Generic, config-driven compliance framework sync runner.

Usage:
    python skills/prowler-compliance/assets/sync_framework.py \
           skills/prowler-compliance/assets/configs/ccc.yaml

Pipeline:
    1. Load and validate the YAML config (fail fast on missing or empty
       required fields — notably ``framework.version``, which silently
       breaks ``get_check_compliance()`` key construction if empty).
    2. Dynamically import the parser module declared in ``parser.module``
       (resolved as ``parsers.{name}`` under this script's directory).
    3. Call ``parser.parse_upstream(config) -> list[dict]`` to get raw
       Prowler-format requirements. The parser owns all upstream-format
       quirks (foreign-prefix AR rewriting, collision renumbering, shape
       handling) and MUST return ids that are unique within the returned
       list.
    4. **Safety net**: assert id uniqueness. The runner raises
       ``ValueError`` on any duplicate — it does NOT silently renumber,
       because mutating a canonical upstream id (e.g. CIS ``1.1.1`` or
       NIST ``AC-2(1)``) would be catastrophic.
    5. Apply generic ``FamilyName`` normalization from
       ``post_processing.family_name_normalization`` (optional).
    6. Preserve legacy ``Checks`` lists from the existing Prowler JSON
       using a config-driven primary key + fallback key chain. CCC uses
       ``(Section, Applicability)`` as fallback; CIS would use
       ``(Section, Profile)``; NIST would use ``(ItemId,)``.
    7. Wrap each provider's requirements in the framework metadata dict
       built from the config templates.
    8. Write each provider's JSON to the path resolved from
       ``output.path_template`` (supports ``{framework}``, ``{version}``
       and ``{provider}`` placeholders).
    9. Pydantic-validate the written JSON via ``Compliance.parse_file()``
       and report the load counts per provider.

The runner is strictly generic — it never mentions CCC, knows nothing
about YAML shapes, and can handle any upstream-backed framework given a
parser module and a config file.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

# Make sibling `parsers/` package importable regardless of the runner's
# invocation directory.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))


# ---------------------------------------------------------------------------
# Config loading and validation
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """Raised when the sync config is malformed or missing required fields."""


def _require(cfg: dict, dotted_path: str) -> Any:
    """Fetch a dotted-path key from nested dicts. Raises ConfigError on
    missing or empty values (empty-string, empty-list, None)."""
    current: Any = cfg
    parts = dotted_path.split(".")
    for i, part in enumerate(parts):
        if not isinstance(current, dict) or part not in current:
            raise ConfigError(f"config: missing required field '{dotted_path}'")
        current = current[part]
    if current in ("", None, [], {}):
        raise ConfigError(f"config: field '{dotted_path}' must not be empty")
    return current


def load_config(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        raise ConfigError(f"config root must be a mapping, got {type(cfg).__name__}")

    # Required fields — fail fast. Empty Version in particular silently
    # breaks get_check_compliance() key construction.
    _require(cfg, "framework.name")
    _require(cfg, "framework.display_name")
    _require(cfg, "framework.version")
    _require(cfg, "framework.description_template")
    _require(cfg, "providers")
    _require(cfg, "output.path_template")
    _require(cfg, "upstream.dir")
    _require(cfg, "parser.module")
    _require(cfg, "post_processing.check_preservation.primary_key")

    providers = cfg["providers"]
    if not isinstance(providers, list) or not providers:
        raise ConfigError("config: 'providers' must be a non-empty list")
    for idx, p in enumerate(providers):
        if not isinstance(p, dict) or "key" not in p or "display" not in p:
            raise ConfigError(
                f"config: providers[{idx}] must have 'key' and 'display' fields"
            )

    return cfg


# ---------------------------------------------------------------------------
# Parser loading
# ---------------------------------------------------------------------------


def load_parser(parser_module_name: str):
    try:
        return importlib.import_module(f"parsers.{parser_module_name}")
    except ImportError as exc:
        raise ConfigError(
            f"cannot import parser 'parsers.{parser_module_name}': {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Post-processing: id uniqueness safety net
# ---------------------------------------------------------------------------


def assert_unique_ids(requirements: list[dict]) -> None:
    """Enforce the parser contract: every requirement must have a unique Id.

    The runner never renumbers silently — a duplicate is a parser bug.
    """
    seen: set[str] = set()
    dups: list[str] = []
    for req in requirements:
        rid = req.get("Id")
        if not rid:
            raise ValueError(f"requirement missing Id: {req}")
        if rid in seen:
            dups.append(rid)
        seen.add(rid)
    if dups:
        raise ValueError(
            f"parser returned duplicate requirement ids: {sorted(set(dups))}"
        )


# ---------------------------------------------------------------------------
# Post-processing: FamilyName normalization
# ---------------------------------------------------------------------------


def normalize_family_names(requirements: list[dict], norm_map: dict[str, str]) -> None:
    """Apply ``Attributes[0].FamilyName`` normalization in place."""
    if not norm_map:
        return
    for req in requirements:
        for attr in req.get("Attributes") or []:
            name = attr.get("FamilyName")
            if name in norm_map:
                attr["FamilyName"] = norm_map[name]


# ---------------------------------------------------------------------------
# Post-processing: legacy check-mapping preservation
# ---------------------------------------------------------------------------


def _freeze(value: Any) -> Any:
    """Make a value hashable for use in composite lookup keys.

    Lists become frozensets (order-insensitive match). Scalars pass through.
    """
    if isinstance(value, list):
        return frozenset(value)
    return value


def _build_fallback_key(attrs: dict, field_names: list[str]) -> tuple | None:
    """Build a composite tuple key from the given attribute field names.

    Returns None if any field is missing or falsy — that key will be
    skipped (the lookup table just won't have an entry for it).
    """
    parts = []
    for name in field_names:
        if name not in attrs:
            return None
        value = attrs[name]
        if value in ("", None, [], {}):
            return None
        parts.append(_freeze(value))
    return tuple(parts)


def load_legacy_check_maps(
    legacy_path: Path,
    primary_key: str,
    fallback_keys: list[list[str]],
) -> tuple[dict[str, list[str]], list[dict[tuple, list[str]]]]:
    """Read the existing Prowler JSON and build lookup tables for check
    preservation.

    Returns
    -------
    by_primary : dict
        ``{primary_value: [checks]}`` — e.g. ``{ar_id: [checks]}``.
    by_fallback : list[dict]
        One lookup dict per entry in ``fallback_keys``. Each maps a
        composite tuple key to its preserved checks list.
    """
    by_primary: dict[str, list[str]] = {}
    by_fallback: list[dict[tuple, list[str]]] = [{} for _ in fallback_keys]

    if not legacy_path.exists():
        return by_primary, by_fallback

    with open(legacy_path) as f:
        data = json.load(f)

    for req in data.get("Requirements") or []:
        checks = req.get("Checks") or []
        # Primary index
        pv = req.get(primary_key)
        if pv:
            bucket = by_primary.setdefault(pv, [])
            for c in checks:
                if c not in bucket:
                    bucket.append(c)

        # Fallback indexes — read from Attributes[0]
        attributes = req.get("Attributes") or []
        if not attributes:
            continue
        attrs = attributes[0]
        for i, field_names in enumerate(fallback_keys):
            key = _build_fallback_key(attrs, field_names)
            if key is None:
                continue
            bucket = by_fallback[i].setdefault(key, [])
            for c in checks:
                if c not in bucket:
                    bucket.append(c)

    return by_primary, by_fallback


def lookup_preserved_checks(
    req: dict,
    by_primary: dict,
    by_fallback: list[dict],
    primary_key: str,
    fallback_keys: list[list[str]],
) -> list[str]:
    """Return preserved check ids for a requirement, trying the primary
    key first then each fallback in order."""
    pv = req.get(primary_key)
    if pv and pv in by_primary:
        return list(by_primary[pv])
    attributes = req.get("Attributes") or []
    if not attributes:
        return []
    attrs = attributes[0]
    for i, field_names in enumerate(fallback_keys):
        key = _build_fallback_key(attrs, field_names)
        if key and key in by_fallback[i]:
            return list(by_fallback[i][key])
    return []


# ---------------------------------------------------------------------------
# Provider output assembly
# ---------------------------------------------------------------------------


def resolve_output_path(template: str, framework: dict, provider_key: str) -> Path:
    return Path(
        template.format(
            provider=provider_key,
            framework=framework["name"].lower(),
            version=framework["version"],
        )
    )


def build_provider_json(
    config: dict,
    provider: dict,
    base_requirements: list[dict],
) -> tuple[dict, dict[str, int]]:
    """Produce the provider-specific JSON dict ready to dump.

    Returns ``(json_dict, counts)`` where ``counts`` tracks how each
    requirement's checks were resolved (primary, fallback, or none).
    """
    framework = config["framework"]
    preservation = config["post_processing"]["check_preservation"]
    primary_key = preservation["primary_key"]
    fallback_keys = preservation.get("fallback_keys") or []

    legacy_path = resolve_output_path(
        config["output"]["path_template"], framework, provider["key"]
    )
    by_primary, by_fallback = load_legacy_check_maps(
        legacy_path, primary_key, fallback_keys
    )

    counts = {"primary": 0, "fallback": 0, "none": 0}
    enriched: list[dict] = []
    for req in base_requirements:
        # Try primary key first
        pv = req.get(primary_key)
        checks: list[str] = []
        source = "none"
        if pv and pv in by_primary:
            checks = list(by_primary[pv])
            source = "primary"
        else:
            attributes = req.get("Attributes") or []
            if attributes:
                attrs = attributes[0]
                for i, field_names in enumerate(fallback_keys):
                    key = _build_fallback_key(attrs, field_names)
                    if key and key in by_fallback[i]:
                        checks = list(by_fallback[i][key])
                        source = "fallback"
                        break
        counts[source] += 1
        enriched.append(
            {
                "Id": req["Id"],
                "Description": req["Description"],
                # Shallow-copy attribute dicts so providers don't share refs
                "Attributes": [dict(a) for a in req.get("Attributes") or []],
                "Checks": checks,
            }
        )

    description = framework["description_template"].format(
        provider_display=provider["display"],
        provider_key=provider["key"],
        framework_name=framework["name"],
        framework_display=framework["display_name"],
        version=framework["version"],
    )
    out = {
        "Framework": framework["name"],
        "Version": framework["version"],
        "Provider": provider["display"],
        "Name": framework["display_name"],
        "Description": description,
        "Requirements": enriched,
    }
    return out, counts


# ---------------------------------------------------------------------------
# Pydantic post-validation
# ---------------------------------------------------------------------------


def pydantic_validate(json_path: Path) -> int:
    """Import Prowler lazily so the runner still works without Prowler
    installed (validation step is skipped in that case)."""
    try:
        from prowler.lib.check.compliance_models import Compliance
    except ImportError:
        print(
            "  note: prowler package not importable — skipping Pydantic validation",
            file=sys.stderr,
        )
        return -1
    try:
        parsed = Compliance.parse_file(str(json_path))
    except Exception as exc:
        raise RuntimeError(
            f"Pydantic validation failed for {json_path}: {exc}"
        ) from exc
    return len(parsed.Requirements)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: sync_framework.py <config.yaml>", file=sys.stderr)
        return 1

    config_path = Path(sys.argv[1])
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    framework_name = config["framework"]["name"]
    upstream_dir = Path(config["upstream"]["dir"])
    if not upstream_dir.exists():
        print(
            f"error: upstream cache dir {upstream_dir} not found\n"
            f"  hint: {config['upstream'].get('fetch_docs', '(see SKILL.md Workflow A Step 1)')}",
            file=sys.stderr,
        )
        return 3

    parser_module_name = config["parser"]["module"]
    print(
        f"Sync: framework={framework_name} version={config['framework']['version']} "
        f"parser={parser_module_name}"
    )

    try:
        parser = load_parser(parser_module_name)
    except ConfigError as exc:
        print(f"parser error: {exc}", file=sys.stderr)
        return 4

    print(f"Parsing upstream from {upstream_dir}...")
    base_requirements = parser.parse_upstream(config)
    print(f"  parser returned {len(base_requirements)} requirements")

    # Safety-net: parser contract
    try:
        assert_unique_ids(base_requirements)
    except ValueError as exc:
        print(f"parser contract violation: {exc}", file=sys.stderr)
        return 5

    # Post-processing: family name normalization
    norm_map = (
        config.get("post_processing", {})
        .get("family_name_normalization")
        or {}
    )
    normalize_family_names(base_requirements, norm_map)

    # Per-provider output
    print()
    for provider in config["providers"]:
        provider_json, counts = build_provider_json(
            config, provider, base_requirements
        )
        out_path = resolve_output_path(
            config["output"]["path_template"],
            config["framework"],
            provider["key"],
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(provider_json, f, indent=2, ensure_ascii=False)
            f.write("\n")

        validated = pydantic_validate(out_path)
        validated_msg = (
            f" pydantic_reqs={validated}" if validated >= 0 else " pydantic=skipped"
        )
        print(
            f"  {provider['key']}: total={len(provider_json['Requirements'])} "
            f"matched_primary={counts['primary']} "
            f"matched_fallback={counts['fallback']} "
            f"new_or_unmatched={counts['none']}{validated_msg}"
        )
        print(f"    wrote {out_path}")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
