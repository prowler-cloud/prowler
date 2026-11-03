"""Ensure shared catalogs preserve the existing provider compliance mappings."""

import json
from collections import defaultdict
from pathlib import Path

import pytest

from prowler.lib.check.compliance_models import (
    get_bulk_compliance_frameworks_universal,
    load_compliance_framework_universal,
)

COMPLIANCE_DIR = Path(__file__).resolve().parents[3] / "prowler" / "compliance"
PROVIDERS_DIR = COMPLIANCE_DIR.parent / "providers"


@pytest.fixture(
    params=[
        ("iso27001_2022", "ISO27001", "2022", 92, "Category"),
        ("soc2", "SOC2", "", 28, "Section"),
        ("pci_4.0", "PCI", "4.0", 110, "Section"),
    ],
    ids=["iso27001", "soc2", "pci"],
)
def catalog(request):
    """Load a shared catalog alongside its original provider requirements."""
    key, framework, version, count, group_by = request.param
    loaded = load_compliance_framework_universal(str(COMPLIANCE_DIR / f"{key}.json"))
    sources = {}
    for path in sorted(COMPLIANCE_DIR.glob(f"*/{key}_*.json")):
        sources[path.parent.name] = json.loads(path.read_text())["Requirements"]
    assert sources
    return key, framework, version, count, group_by, loaded, sources


def _control_id(key, requirement):
    """PCI legacy row IDs are check-specific; Section records the control ID."""
    if key == "pci_4.0":
        return requirement["Attributes"][0]["Section"].split(":", 1)[0].strip()
    return requirement["Id"]


def test_shared_catalog_metadata(catalog):
    _, framework, version, count, _, loaded, sources = catalog
    assert loaded is not None
    assert loaded.framework == framework
    assert loaded.version == version
    assert len(loaded.requirements) == count
    assert set(loaded.get_providers()) == set(sources)


def test_control_ids_preserve_source_catalog_scope(catalog):
    key, _, _, _, _, loaded, sources = catalog
    ids = [requirement.id for requirement in loaded.requirements]
    assert len(ids) == len(set(ids))
    assert set(ids) == {
        _control_id(key, requirement)
        for requirements in sources.values()
        for requirement in requirements
    }


def test_provider_mappings_preserved_per_control(catalog):
    key, _, _, _, _, loaded, sources = catalog
    for provider, requirements in sources.items():
        expected = defaultdict(set)
        for requirement in requirements:
            expected[_control_id(key, requirement)].update(requirement["Checks"])
        for requirement in loaded.requirements:
            checks = requirement.checks[provider]
            assert len(checks) == len(set(checks))
            assert set(checks) == expected[requirement.id], (
                provider,
                requirement.id,
            )


def test_guardrails_preserved_and_scoped_to_provider(catalog):
    key, _, _, _, _, loaded, sources = catalog
    expected = defaultdict(set)
    for provider, requirements in sources.items():
        for requirement in requirements:
            for constraint in requirement.get("ConfigRequirements", []):
                scoped = {**constraint, "Provider": provider}
                expected[_control_id(key, requirement)].add(
                    json.dumps(scoped, sort_keys=True)
                )
    for requirement in loaded.requirements:
        constraints = requirement.config_requirements or []
        assert {json.dumps(c.dict(), sort_keys=True) for c in constraints} == expected[
            requirement.id
        ]
        for constraint in constraints:
            assert constraint.Check in requirement.checks[constraint.Provider]


def test_all_referenced_checks_exist(catalog):
    _, _, _, _, _, loaded, sources = catalog
    for provider in sources:
        inventory = {
            path.name.removesuffix(".metadata.json")
            for path in (PROVIDERS_DIR / provider / "services").rglob("*.metadata.json")
        }
        assert inventory
        for requirement in loaded.requirements:
            assert set(requirement.checks[provider]) <= inventory


def test_output_grouping_matches_declared_attributes(catalog):
    _, _, _, _, group_by, loaded, _ = catalog
    assert loaded.outputs.table_config.group_by == group_by
    assert loaded.outputs.pdf_config.group_by_field == group_by
    metadata = {attribute.key: attribute for attribute in loaded.attributes_metadata}
    groups = {requirement.attributes[group_by] for requirement in loaded.requirements}
    assert groups == set(metadata[group_by].enum)
    assert groups == set(loaded.outputs.pdf_config.sections)
    for chart in loaded.outputs.pdf_config.charts:
        assert chart["group_by"] in metadata


def test_shared_catalog_discovered_for_existing_providers(catalog):
    key, _, _, _, _, _, sources = catalog
    for provider in sources:
        bulk = get_bulk_compliance_frameworks_universal(provider)
        assert key in bulk
        assert f"{key}_{provider}" in bulk
