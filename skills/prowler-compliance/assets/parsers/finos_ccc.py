"""
FINOS Common Cloud Controls (CCC) YAML parser.

Reads cached upstream YAML files and emits Prowler-format requirements
(``{Id, Description, Attributes: [...], Checks: []}``). This module is
agnostic to providers, JSON output paths, framework metadata and legacy
check-mapping preservation — those are handled by ``sync_framework.py``.

Contract
--------
``parse_upstream(config: dict) -> list[dict]``
    Returns a list of Prowler-format requirement dicts with **guaranteed
    unique ids**. Foreign-prefix AR rewriting and genuine collision
    renumbering both happen inside this module — the runner treats id
    uniqueness as a contract violation, not as something to fix.

Config keys consumed
--------------------
This parser reads the following config entries (the rest of the config is
opaque to it):

- ``upstream.dir``              — directory containing the cached YAMLs
- ``parser.catalog_files``      — ordered list of YAML filenames to load
- ``parser.family_id_title``    — suffix → canonical family title (shape 2)
- ``parser.family_id_description`` — suffix → family description (shape 2)

Upstream shapes
---------------
FINOS CCC catalogs come in two shapes:

1. ``control-families: [{title, description, controls: [...]}]``
   (used by most catalogs)
2. ``controls: [{id, family: "CCC.X.Y", ...}]`` (no families wrapper; used
   by ``storage/object``). The ``family`` field references a family id with
   no human-readable title in the file — the title/description come from
   ``config.parser.family_id_title`` / ``family_id_description``.

Id rewriting rules
------------------
- **Foreign-prefix rewriting**: upstream intentionally aliases requirements
  across catalogs by keeping the original prefix (e.g. ``CCC.AuditLog.CN08.AR01``
  appears nested under ``CCC.Logging.CN03``). Prowler requires unique ids
  within a catalog file, so we rename the AR to fit its parent control:
  ``CCC.Logging.CN03.AR01``. See ``rewrite_ar_id()``.
- **Genuine collision renumbering**: sometimes upstream has a real typo
  where two distinct requirements share the same id (e.g.
  ``CCC.Core.CN14.AR02`` appears twice for 30-day and 14-day backup variants).
  The second copy is renumbered to the next free AR number within the
  control. See the ``seen_ids`` logic in ``emit_requirement()``.
"""
from __future__ import annotations

from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def clean(value: str | None) -> str:
    """Trim and collapse internal whitespace/newlines into single spaces.

    Upstream YAML uses ``|`` block scalars that preserve newlines; Prowler
    stores descriptions as single-line text.
    """
    if not value:
        return ""
    return " ".join(value.split())


def flatten_mappings(mappings):
    """Convert upstream ``{reference-id, entries: [{reference-id, ...}]}`` to
    Prowler's ``{ReferenceId, Identifiers: [...]}``.
    """
    if not mappings:
        return []
    out = []
    for m in mappings:
        ids = []
        for entry in m.get("entries") or []:
            eid = entry.get("reference-id")
            if eid:
                ids.append(eid)
        out.append({"ReferenceId": m.get("reference-id", ""), "Identifiers": ids})
    return out


def ar_prefix(ar_id: str) -> str:
    """Return the first three dot-segments of an AR id (the parent control).

    e.g. ``CCC.Core.CN01.AR01`` -> ``CCC.Core.CN01``.
    """
    return ".".join(ar_id.split(".")[:3])


def rewrite_ar_id(parent_control_id: str, original_ar_id: str, ar_index: int) -> str:
    """If an AR's id doesn't share its parent control's prefix, rename it.

    Example
    -------
    parent ``CCC.Logging.CN03`` + AR id ``CCC.AuditLog.CN08.AR01`` with
    index 0 -> ``CCC.Logging.CN03.AR01``.
    """
    if ar_prefix(original_ar_id) == parent_control_id:
        return original_ar_id
    return f"{parent_control_id}.AR{ar_index + 1:02d}"


def emit_requirement(
    control: dict,
    family_name: str,
    family_desc: str,
    seen_ids: set[str],
    requirements: list[dict],
) -> None:
    """Translate one FINOS control + its assessment-requirements into
    Prowler-format requirement dicts and append them to ``requirements``.

    Applies foreign-prefix rewriting and genuine-collision renumbering so
    the final list is guaranteed to have unique ids.
    """
    control_id = clean(control.get("id"))
    control_title = clean(control.get("title"))
    section = f"{control_id} {control_title}".strip()
    objective = clean(control.get("objective"))
    threat_mappings = flatten_mappings(control.get("threat-mappings"))
    guideline_mappings = flatten_mappings(control.get("guideline-mappings"))
    ars = control.get("assessment-requirements") or []
    for idx, ar in enumerate(ars):
        raw_id = clean(ar.get("id"))
        if not raw_id:
            continue
        new_id = rewrite_ar_id(control_id, raw_id, idx)
        # Renumber on genuine upstream collision (find next free AR number)
        if new_id in seen_ids:
            base = ".".join(new_id.split(".")[:-1])
            n = 1
            while f"{base}.AR{n:02d}" in seen_ids:
                n += 1
            new_id = f"{base}.AR{n:02d}"
        seen_ids.add(new_id)

        requirements.append(
            {
                "Id": new_id,
                "Description": clean(ar.get("text")),
                "Attributes": [
                    {
                        "FamilyName": family_name,
                        "FamilyDescription": family_desc,
                        "Section": section,
                        "SubSection": "",
                        "SubSectionObjective": objective,
                        "Applicability": list(ar.get("applicability") or []),
                        "Recommendation": clean(ar.get("recommendation")),
                        "SectionThreatMappings": threat_mappings,
                        "SectionGuidelineMappings": guideline_mappings,
                    }
                ],
                "Checks": [],
            }
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_upstream(config: dict) -> list[dict]:
    """Walk upstream YAMLs and emit Prowler-format requirements.

    Handles both top-level shapes (``control-families`` and ``controls``).
    Ids are guaranteed unique in the returned list.
    """
    upstream_dir = Path(config["upstream"]["dir"])
    parser_cfg = config.get("parser") or {}
    catalog_files = parser_cfg.get("catalog_files") or []
    family_id_title = parser_cfg.get("family_id_title") or {}
    family_id_description = parser_cfg.get("family_id_description") or {}

    requirements: list[dict] = []
    seen_ids: set[str] = set()

    for filename in catalog_files:
        path = upstream_dir / filename
        if not path.exists():
            # The runner handles fatal errors; a missing optional catalog
            # file is surfaced as a warning via print to stderr.
            import sys

            print(f"warn: missing upstream file {filename}", file=sys.stderr)
            continue
        with open(path) as f:
            doc = yaml.safe_load(f) or {}

        # Shape 1: control-families wrapper
        for family in doc.get("control-families") or []:
            family_name = clean(family.get("title"))
            family_desc = clean(family.get("description"))
            for control in family.get("controls") or []:
                emit_requirement(
                    control, family_name, family_desc, seen_ids, requirements
                )

        # Shape 2: top-level controls with family reference id
        for control in doc.get("controls") or []:
            family_ref = clean(control.get("family"))
            suffix = family_ref.split(".")[-1] if family_ref else ""
            family_name = family_id_title.get(suffix, suffix or "Data")
            family_desc = family_id_description.get(suffix, "")
            emit_requirement(
                control, family_name, family_desc, seen_ids, requirements
            )

    return requirements
