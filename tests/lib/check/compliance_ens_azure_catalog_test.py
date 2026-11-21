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


def test_requirements_have_attributes():
    assert not requirements_without_attributes(REQUIREMENTS)


def test_execution_mode_follows_from_the_checks():
    assert not execution_mode_mismatches(REQUIREMENTS)


def test_group_ids_are_measures_of_the_rd():
    assert not malformed_measure_ids(REQUIREMENTS)


def test_measures_are_filed_under_their_block_and_group():
    assert not misfiled_measures(REQUIREMENTS)


def test_requirement_ids_name_their_measure():
    assert not misnamed_requirements(REQUIREMENTS, "az")


# The measures in the summary table of CCN-STIC-884A, the CCN guide to configuring
# Azure for the ENS (May 2024 edition). The guide gives its requirements no ids, so
# the catalog keeps at least one requirement for each measure of the table.
CCN_STIC_884A_SUMMARY_MEASURES = (
    "op.acc.1",
    "op.acc.2",
    "op.acc.3",
    "op.acc.5",
    "op.acc.6",
    "op.exp.8",
    "op.exp.10",
    "op.cont.2",
    "op.cont.3",
    "op.mon.1",
    "op.mon.2",
    "op.mon.3",
    "mp.com.1",
    "mp.com.2",
    "mp.com.3",
    "mp.com.4",
    "mp.info.2",
    "mp.info.6",
    "mp.s.4",
)


def test_covers_the_summary_table_of_ccn_stic_884a():
    measures = {
        attribute["IdGrupoControl"]
        for requirement in REQUIREMENTS
        for attribute in requirement["Attributes"]
    }
    assert sorted(set(CCN_STIC_884A_SUMMARY_MEASURES) - measures) == []
