#!/usr/bin/env python3
"""
Upstream YAML → Prowler JSON sync generator for FINOS Common Cloud Controls
(CCC). Drop-in template for any upstream-backed framework — adapt the catalog
list, family normalization, and upstream path.

Pipeline:
    1. Parse cached upstream YAMLs from /tmp/ccc_upstream/ (run the
       fetch-upstream step first — see SKILL.md Workflow A Step 1).
    2. Handle BOTH upstream shapes:
         - `control-families: [{title, description, controls: [...]}]`
         - `controls: [{id, family: "CCC.X.Y", ...}]` (no families wrapper)
       Shape 2 is used by FINOS CCC's storage/object catalog. A sync that
       only handles shape 1 silently drops the shape-2 catalog.
    3. Rewrite foreign-prefix AR ids to match their parent control id.
       Upstream intentionally aliases `CCC.AuditLog.CN08.AR01` into
       `CCC.Logging.CN03` — Prowler requires unique ids within a catalog, so
       rename to `CCC.Logging.CN03.AR01`.
    4. Renumber genuine upstream collisions (e.g. `CCC.Core.CN14.AR02`
       appears twice for two different backup-window variants → second copy
       becomes `CCC.Core.CN14.AR03`).
    5. Normalize FamilyName variants (e.g. collapse "Logging & Monitoring" /
       "Logging and Metrics Publication" into "Logging and Monitoring").
    6. Preserve existing check mappings from the legacy Prowler JSON.
       Lookup keys: try (Id) first, then (Section, frozenset(Applicability))
       to recover mappings whose ids were rewritten or renumbered.
    7. Write the new JSONs with `Version` populated (never empty).

Usage:
    # 1. Fetch upstream catalogs to /tmp/ccc_upstream/ (one YAML per catalog)
    # 2. Run:
    python skills/prowler-compliance/assets/sync_ccc_template.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Configure for your framework
# ---------------------------------------------------------------------------

UPSTREAM_DIR = Path("/tmp/ccc_upstream")
PROWLER_DIR = Path("prowler/compliance")
PROVIDERS = ["aws", "azure", "gcp"]
PROVIDER_DISPLAY = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}

# Upstream version (MUST be populated — empty Version breaks key construction)
CCC_VERSION = "v2025.10"

# Catalog files in load order. Core first so its ARs render first.
CATALOG_FILES = [
    "core_ccc.yaml",
    "management_auditlog.yaml",
    "management_logging.yaml",
    "management_monitoring.yaml",
    "storage_object.yaml",
    "networking_loadbalancer.yaml",
    "networking_vpc.yaml",
    "crypto_key.yaml",
    "crypto_secrets.yaml",
    "database_warehouse.yaml",
    "database_vector.yaml",
    "database_relational.yaml",
    "devtools_build.yaml",
    "devtools_container-registry.yaml",
    "identity_iam.yaml",
    "ai-ml_gen-ai.yaml",
    "ai-ml_mlde.yaml",
    "app-integration_message.yaml",
    "compute_serverless-computing.yaml",
]

# Collapse FamilyName variants (UI groups by exact value)
FAMILY_NAME_NORMALIZATION = {
    "Logging & Monitoring": "Logging and Monitoring",
    "Logging and Metrics Publication": "Logging and Monitoring",
}

# Shape 2 catalogs reference family via id (e.g. "CCC.ObjStor.Data") with no
# human title in the file. Map id suffix → canonical title.
FAMILY_ID_TITLE = {
    "Data": "Data",
    "IAM": "Identity and Access Management",
    "Identity": "Identity and Access Management",
    "Encryption": "Encryption",
    "Logging": "Logging and Monitoring",
    "Network": "Network Security",
    "Availability": "Availability",
    "Integrity": "Integrity",
    "Confidentiality": "Confidentiality",
}
FAMILY_ID_DESCRIPTION = {
    "Data": (
        "The Data control family ensures the confidentiality, integrity, "
        "availability, and sovereignty of data across its lifecycle."
    ),
    "IAM": (
        "The Identity and Access Management control family ensures that "
        "only trusted and authenticated entities can access resources."
    ),
}


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------

def clean(value: str | None) -> str:
    """Trim and collapse internal whitespace/newlines into single spaces.

    Upstream YAML uses `|` block scalars that preserve newlines; Prowler stores
    descriptions as single-line text.
    """
    if not value:
        return ""
    return " ".join(value.split())


def normalize_family(name: str) -> str:
    return FAMILY_NAME_NORMALIZATION.get(name, name)


def flatten_mappings(mappings):
    """Convert upstream {reference-id, entries: [{reference-id, ...}]} to
    Prowler's {ReferenceId, Identifiers: [...]}."""
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
    return ".".join(ar_id.split(".")[:3])


def rewrite_ar_id(parent_control_id: str, original_ar_id: str, ar_index: int) -> str:
    """If an AR's id doesn't share its parent control's prefix, rename it.

    e.g., parent `CCC.Logging.CN03` + AR id `CCC.AuditLog.CN08.AR01` with
    index 0 -> `CCC.Logging.CN03.AR01`.
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
        # Renumber on genuine upstream collision
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


def load_upstream_requirements() -> list[dict]:
    """Walk upstream YAMLs and emit Prowler-format requirements (no Checks).

    Handles both top-level shapes.
    """
    requirements: list[dict] = []
    seen_ids: set[str] = set()
    for filename in CATALOG_FILES:
        path = UPSTREAM_DIR / filename
        if not path.exists():
            print(f"warn: missing upstream file {filename}", file=sys.stderr)
            continue
        with open(path) as f:
            doc = yaml.safe_load(f) or {}

        # Shape 1: control-families
        for family in doc.get("control-families") or []:
            family_name = normalize_family(clean(family.get("title")))
            family_desc = clean(family.get("description"))
            for control in family.get("controls") or []:
                emit_requirement(
                    control, family_name, family_desc, seen_ids, requirements
                )

        # Shape 2: top-level controls with family reference id
        for control in doc.get("controls") or []:
            family_ref = clean(control.get("family"))
            suffix = family_ref.split(".")[-1] if family_ref else ""
            family_name = normalize_family(
                FAMILY_ID_TITLE.get(suffix, suffix or "Data")
            )
            family_desc = FAMILY_ID_DESCRIPTION.get(suffix, "")
            emit_requirement(
                control, family_name, family_desc, seen_ids, requirements
            )

    return requirements


# ---------------------------------------------------------------------------
# Check-mapping preservation from legacy Prowler JSON
# ---------------------------------------------------------------------------

def load_existing_check_maps(provider: str):
    """Return two lookup maps from the legacy Prowler JSON:

    - by_id:      ar_id -> [checks]
    - by_section: (section, frozenset(applicability)) -> [checks]
    """
    path = PROWLER_DIR / provider / f"ccc_{provider}.json"
    by_id: dict[str, list[str]] = {}
    by_section: dict[tuple, list[str]] = {}
    if not path.exists():
        return by_id, by_section
    with open(path) as f:
        data = json.load(f)
    for req in data.get("Requirements", []):
        rid = req.get("Id")
        checks = req.get("Checks") or []
        if rid:
            existing = by_id.setdefault(rid, [])
            for c in checks:
                if c not in existing:
                    existing.append(c)
        for attr in req.get("Attributes", []) or []:
            section = attr.get("Section", "")
            app = frozenset(attr.get("Applicability") or [])
            if not section:
                continue
            key = (section, app)
            bucket = by_section.setdefault(key, [])
            for c in checks:
                if c not in bucket:
                    bucket.append(c)
    return by_id, by_section


def lookup_checks(req: dict, by_id, by_section) -> tuple[list[str], str]:
    """Return (checks, source) where source is 'id' | 'section' | 'none'."""
    rid = req["Id"]
    if rid in by_id:
        return list(by_id[rid]), "id"
    attr = req["Attributes"][0]
    key = (attr["Section"], frozenset(attr.get("Applicability") or []))
    if key in by_section:
        return list(by_section[key]), "section"
    return [], "none"


def build_provider_json(provider: str, base_requirements: list[dict]) -> dict:
    by_id, by_section = load_existing_check_maps(provider)
    counts = {"id": 0, "section": 0, "none": 0}
    enriched = []
    for req in base_requirements:
        checks, source = lookup_checks(req, by_id, by_section)
        counts[source] += 1
        enriched.append(
            {
                "Id": req["Id"],
                "Description": req["Description"],
                "Attributes": [dict(a) for a in req["Attributes"]],
                "Checks": checks,
            }
        )
    print(
        f"  {provider}: total={len(enriched)} "
        f"matched_by_id={counts['id']} "
        f"matched_by_section={counts['section']} "
        f"new_or_unmatched={counts['none']}"
    )
    return {
        "Framework": "CCC",
        "Version": CCC_VERSION,
        "Provider": PROVIDER_DISPLAY[provider],
        "Name": "Common Cloud Controls Catalog (CCC)",
        "Description": (
            f"Common Cloud Controls Catalog (CCC) for {PROVIDER_DISPLAY[provider]}"
        ),
        "Requirements": enriched,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    if not UPSTREAM_DIR.exists():
        print(
            f"error: upstream cache dir {UPSTREAM_DIR} not found\n"
            f"See SKILL.md Workflow A Step 1 for fetching upstream YAMLs.",
            file=sys.stderr,
        )
        return 1
    print("Parsing upstream YAML files...")
    base = load_upstream_requirements()
    print(f"  total upstream ARs after id-fix: {len(base)}")

    # Sanity check: no duplicate ids after rewriting / renumbering
    ids = [r["Id"] for r in base]
    dups = [i for i in set(ids) if ids.count(i) > 1]
    if dups:
        print(
            f"error: produced duplicate IDs after fix: {dups}\n"
            f"Check emit_requirement() collision handling.",
            file=sys.stderr,
        )
        return 2

    print()
    for provider in PROVIDERS:
        out = build_provider_json(provider, base)
        out_path = PROWLER_DIR / provider / f"ccc_{provider}.json"
        with open(out_path, "w") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"  wrote {out_path}")
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
