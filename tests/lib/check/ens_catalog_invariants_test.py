"""The invariants of the ENS catalogs report what they are meant to report."""

import pytest

from tests.lib.check.ens_catalog_invariants import (
    execution_mode_mismatches,
    malformed_measure_ids,
    misfiled_measures,
)


def _requirement(
    group: str,
    marco: str = "operacional",
    categoria: str = "control de acceso",
    mode: str = "manual",
    checks: tuple = (),
) -> dict:
    return {
        "Id": f"{group}.aws.iam.1",
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
    "group", ["op.acc.6", "op.acc.6.r9", "op.exp.10", "mp.com.4", "mp.s.4.r1", "org.4"]
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
    ],
)
def test_a_code_that_is_not_a_measure_is_reported(group):
    assert malformed_measure_ids([_requirement(group)]) == [
        (f"{group}.aws.iam.1", group)
    ]


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
