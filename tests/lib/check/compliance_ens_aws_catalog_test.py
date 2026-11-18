"""The ENS RD 311/2022 catalog for AWS keeps the invariants of every ENS catalog."""

from tests.lib.check.ens_catalog_invariants import (
    execution_mode_mismatches,
    load_requirements,
    malformed_measure_ids,
    misfiled_measures,
    misnamed_requirements,
    requirements_without_attributes,
)

REQUIREMENTS = load_requirements("aws")

# Ids that name a measure other than the one they are filed under. The API stores the id
# as a key, so renaming them is left for the maintainers to decide in #13416.
PENDING_RENAMES = {
    "op.ext.7.aws.am.1",
    "op.exp.1.r3.aws.tag.1",
    "op.exp.3.r4.aws.cfg.2",
    "mp.sw.2.r1.aws.cfgd.1",
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
    assert set(misnamed_requirements(REQUIREMENTS, "aws")) == PENDING_RENAMES
