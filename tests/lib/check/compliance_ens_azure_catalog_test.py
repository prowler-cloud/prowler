"""The ENS RD 311/2022 catalog for Azure keeps the invariants of every ENS catalog."""

from tests.lib.check.ens_catalog_invariants import (
    execution_mode_mismatches,
    load_requirements,
    malformed_measure_ids,
    misfiled_measures,
    misnamed_requirements,
    requirements_without_attributes,
)

REQUIREMENTS = load_requirements("azure")

# Ids that are not built from the measure they are filed under and the provider, with
# that measure: a mistyped measure, the reinforcement after the provider, or nothing
# after the provider. The API stores the id as a key, so renaming them is left for the
# maintainers to decide in #13418.
PENDING_RENAMES = {
    "op.acc.1.az.r1.eid.1": "op.acc.1.r1",
    "op.acc.2.az.r1.eid.1": "op.acc.2.r1",
    "opc.acc.5.az.eid.1": "op.acc.5",
    "op.acc.6.r9.az": "op.acc.6.r9",
    "op.exp8.r2.az.wc.1": "op.exp.8.r2",
    "op.con.3.az.pd.1": "op.cont.3",
    "mp.com.4.r2..az.sa.1": "mp.com.4.r2",
}


def test_requirements_have_attributes():
    assert not requirements_without_attributes(REQUIREMENTS)


def test_execution_mode_follows_from_the_checks():
    assert not execution_mode_mismatches(REQUIREMENTS)


def test_group_ids_are_measures_of_the_rd():
    assert not malformed_measure_ids(REQUIREMENTS)


def test_measures_are_filed_under_their_block_and_group():
    assert not misfiled_measures(REQUIREMENTS)


def test_requirement_ids_name_their_measure_but_for_the_pending_renames():
    assert sorted(misnamed_requirements(REQUIREMENTS, "az")) == sorted(
        PENDING_RENAMES.items()
    )
