"""The invariants of the ENS catalogs report what they are meant to report."""

from typing import Optional

import pytest

from tests.lib.check.ens_catalog_invariants import (
    CATEGORIAS,
    ORGANISATIONAL,
    REINFORCEMENTS,
    execution_mode_mismatches,
    malformed_measure_ids,
    misfiled_measures,
    misnamed_requirements,
    requirements_without_attributes,
)

# Number of measures of each group in the summary table of Annex II of Real Decreto
# 311/2022, 73 in all.
MEASURES = {
    "org": 4,
    "op.pl": 5,
    "op.acc": 6,
    "op.exp": 10,
    "op.ext": 4,
    "op.nub": 1,
    "op.cont": 4,
    "op.mon": 3,
    "mp.if": 7,
    "mp.per": 4,
    "mp.eq": 4,
    "mp.com": 4,
    "mp.si": 5,
    "mp.sw": 2,
    "mp.info": 6,
    "mp.s": 4,
}


def _requirement(
    group: str,
    marco: str = "operacional",
    categoria: str = "control de acceso",
    mode: str = "manual",
    checks: tuple = (),
    requirement_id: Optional[str] = None,
) -> dict:
    return {
        "Id": requirement_id or f"{group}.aws.iam.1",
        "Checks": list(checks),
        "Attributes": [
            {
                "IdGrupoControl": group,
                "Marco": marco,
                "Categoria": categoria,
                "ModoEjecucion": mode,
            }
        ],
    }


@pytest.mark.parametrize(
    "group",
    [
        "op.acc.6",
        "op.acc.6.r9",
        "op.exp.10",
        "mp.com.4",
        "mp.s.4.r1",
        "mp.sw.2.r2",
        "org.4",
    ],
)
def test_the_code_of_a_measure_is_accepted(group):
    assert not malformed_measure_ids([_requirement(group)])


@pytest.mark.parametrize(
    "group",
    [
        "op.acc.6.9",  # reinforcement without its "r"
        "op.mon.3 ",  # trailing space
        "opc.acc.1",  # mistyped block
        "mp.comm.4",  # mistyped group
        "op.unknown.1",  # group that is not in the RD
        "op.acc.7",  # op.acc has six measures
        "mp.sw.3",  # mp.sw has two measures
        "org.5",  # the organisational framework has four measures
        "op.acc.0",  # measures are numbered from 1
        "op.acc.6.r0",  # reinforcements are numbered from 1
        "op.acc.6.r10",  # op.acc.6 has R1 to R9
        "mp.sw.2.r3",  # mp.sw.2 has R1 and R2
        "op.acc.4.r1",  # op.acc.4 has no reinforcements
        "op.exp.1\u0660",  # ARABIC-INDIC DIGIT ZERO, which is not an ASCII digit
        pytest.param("op.acc.6.r" + "9" * 5000, id="reinforcement of 5000 digits"),
    ],
)
def test_a_code_that_is_not_a_measure_is_reported(group):
    assert malformed_measure_ids([_requirement(group)]) == [
        (f"{group}.aws.iam.1", group)
    ]


def test_the_reinforcements_cover_the_measures_and_the_groups_of_the_rd():
    assert {
        group: len(measures) for group, measures in REINFORCEMENTS.items()
    } == MEASURES
    assert set(REINFORCEMENTS) == {ORGANISATIONAL, *CATEGORIAS}


def test_a_requirement_without_attributes_is_reported():
    described = _requirement("op.acc.1")
    empty = {**_requirement("op.acc.2"), "Attributes": []}
    missing = _requirement("op.acc.3")
    del missing["Attributes"]
    assert requirements_without_attributes([described, empty, missing]) == [
        empty["Id"],
        missing["Id"],
    ]


def test_the_other_invariants_have_nothing_to_say_without_attributes():
    bare = {"Id": "op.acc.1.aws.iam.1", "Checks": []}
    assert not execution_mode_mismatches([bare])
    assert not malformed_measure_ids([bare])
    assert not misfiled_measures([bare])
    assert not misnamed_requirements([bare], "aws")


def test_a_measure_filed_under_its_block_and_group_is_accepted():
    requirement = _requirement(
        "mp.sw.2.r1",
        "medidas de protección",
        "protección de las aplicaciones informáticas",
    )
    assert not misfiled_measures([requirement])


@pytest.mark.parametrize(
    "marco, categoria",
    [
        ("medidas de protección", "protección de la información"),  # group of mp.info
        ("operacional", "protección de las aplicaciones informáticas"),  # another block
    ],
)
def test_a_measure_filed_under_another_block_or_group_is_reported(marco, categoria):
    requirement = _requirement("mp.sw.2.r1", marco, categoria)
    assert misfiled_measures([requirement]) == [
        ("mp.sw.2.r1.aws.iam.1", marco, categoria)
    ]


@pytest.mark.parametrize(
    "mode, checks, mismatches",
    [
        ("automático", ("iam_check",), []),
        ("manual", (), []),
        ("manual", ("iam_check",), [("op.acc.1.aws.iam.1", "manual")]),
        ("automático", (), [("op.acc.1.aws.iam.1", "automático")]),
        ("automatico", ("iam_check",), [("op.acc.1.aws.iam.1", "automatico")]),
    ],
)
def test_the_execution_mode_has_to_follow_from_the_checks(mode, checks, mismatches):
    requirement = _requirement("op.acc.1", mode=mode, checks=checks)
    assert execution_mode_mismatches([requirement]) == mismatches


@pytest.mark.parametrize(
    "requirement_id",
    [
        "op.acc.2.r1.aws.iam.1",
        "op.acc.2.r1.aws.1",  # the suffix may be a single part
    ],
)
def test_an_id_built_from_its_measure_and_provider_is_accepted(requirement_id):
    requirement = _requirement("op.acc.2.r1", requirement_id=requirement_id)
    assert not misnamed_requirements([requirement], "aws")


@pytest.mark.parametrize(
    "requirement_id",
    [
        "op.acc.2.aws.iam.1",  # lacks the reinforcement of its group
        "op.acc.2.r10.aws.iam.1",  # another reinforcement that starts the same way
        "op.acc.2.aws.r1.iam.1",  # reinforcement after the provider
        "opc.acc.2.r1.aws.iam.1",  # mistyped block
        "op.acc.2.r1..aws.iam.1",  # doubled dot
        "op.acc.2.r1.az.iam.1",  # another provider
        "op.acc.2.r1.aws",  # nothing after the provider
        "op.acc.2.r1.aws.",  # empty suffix
        "op.acc.2.r1.aws.iam.",  # suffix that ends with a dot
        "op.acc.2.r1.aws..1",  # suffix with an empty part
        "op.acc.2.r1.aws.IAM.1",  # suffix in capitals
        "op.acc.2.r1.aws.iam.1 ",  # trailing space
    ],
)
def test_an_id_not_built_from_its_measure_and_provider_is_reported(requirement_id):
    requirement = _requirement("op.acc.2.r1", requirement_id=requirement_id)
    assert misnamed_requirements([requirement], "aws") == [
        (requirement_id, "op.acc.2.r1")
    ]
