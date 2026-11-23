"""Invariants of the ENS RD 311/2022 catalog for Microsoft 365.

The catalog holds the requirements of several CCN-STIC guides (885A for the shared
services, then one guide per service) in a single file, so the same RD measure collects
requirements from different guides. These tests keep them filed the same way:

- the requirement id names the RD measure it is filed under, the service and a number,
- every requirement of a measure carries the same measure metadata, because the outputs
  and the UI group the requirements by those values,
- the execution mode says whether Prowler evaluates the requirement, so a requirement
  that loses or gains its checks cannot keep the previous mode.
"""

import json
import os
import re
from collections import defaultdict

import pytest

CATALOG_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "prowler",
        "compliance",
        "m365",
        "ens_rd2022_m365.json",
    )
)

# <measure>.m365.<service>.<number>, where the measure may be a reinforcement (.rN).
REQUIREMENT_ID = re.compile(
    r"(?P<measure>(?:op|mp)\.[a-z]+\.\d+(?:\.r\d+)?)\.m365\.(?P<service>[a-z0-9]+)\.(?P<number>\d+)"
)
MEASURE_METADATA = ("Marco", "Categoria", "Nivel", "Tipo", "Dimensiones")


def _requirements() -> list[dict]:
    with open(CATALOG_PATH, encoding="utf-8") as catalog:
        return json.load(catalog)["Requirements"]


@pytest.mark.parametrize(
    "requirement",
    [
        pytest.param(requirement, id=requirement["Id"])
        for requirement in _requirements()
    ],
)
class TestENSM365Requirement:
    def test_id_names_the_measure_it_is_filed_under(self, requirement):
        match = REQUIREMENT_ID.fullmatch(requirement["Id"])
        assert match, f"{requirement['Id']} is not <measure>.m365.<service>.<number>"
        for attribute in requirement["Attributes"]:
            assert attribute["IdGrupoControl"] == match["measure"]

    def test_execution_mode_matches_the_checks(self, requirement):
        expected = "automático" if requirement["Checks"] else "manual"
        for attribute in requirement["Attributes"]:
            assert attribute["ModoEjecucion"] == expected


def test_requirements_of_a_measure_share_its_metadata():
    metadata_by_measure = defaultdict(set)
    for requirement in _requirements():
        for attribute in requirement["Attributes"]:
            metadata_by_measure[attribute["IdGrupoControl"]].add(
                (
                    requirement["Description"],
                    *(
                        json.dumps(attribute[key], ensure_ascii=False)
                        for key in MEASURE_METADATA
                    ),
                )
            )

    inconsistent = {
        measure: sorted(metadata)
        for measure, metadata in metadata_by_measure.items()
        if len(metadata) > 1
    }
    assert not inconsistent


def test_requirements_are_numbered_consecutively_per_measure_and_service():
    numbers = defaultdict(list)
    for requirement in _requirements():
        match = REQUIREMENT_ID.fullmatch(requirement["Id"])
        numbers[(match["measure"], match["service"])].append(int(match["number"]))

    gaps = {
        key: found
        for key, found in numbers.items()
        if sorted(found) != list(range(1, len(found) + 1))
    }
    assert not gaps
