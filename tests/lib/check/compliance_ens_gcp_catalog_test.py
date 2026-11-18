"""The ENS RD 311/2022 catalog for GCP keeps the invariants of every ENS catalog."""

from tests.lib.check.ens_catalog_invariants import (
    execution_mode_mismatches,
    load_requirements,
    malformed_measure_ids,
    misfiled_measures,
    misnamed_requirements,
    requirements_without_attributes,
)

REQUIREMENTS = load_requirements("gcp")

# Id with nothing after the provider, and the measure it is filed under. CCN-STIC-888B
# gives it no service or number, so completing it is left for the maintainers to decide
# in #13420.
PENDING_RENAMES = {"op.exp.4.r2.gcp": "op.exp.4.r2"}


def test_requirements_have_attributes():
    assert not requirements_without_attributes(REQUIREMENTS)


def test_execution_mode_follows_from_the_checks():
    assert not execution_mode_mismatches(REQUIREMENTS)


def test_group_ids_are_measures_of_the_rd():
    assert not malformed_measure_ids(REQUIREMENTS)


def test_measures_are_filed_under_their_block_and_group():
    assert not misfiled_measures(REQUIREMENTS)


def test_requirement_ids_name_their_measure_but_for_the_pending_renames():
    assert dict(misnamed_requirements(REQUIREMENTS, "gcp")) == PENDING_RENAMES
