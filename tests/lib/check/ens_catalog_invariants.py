"""Invariants of the ENS RD 311/2022 catalogs, shared by the tests of each provider.

Every provider keeps its catalog in
``prowler/compliance/<provider>/ens_rd2022_<provider>.json``. The outputs, the API
report and the UI group the requirements by the metadata of the measure they are filed
under, so every requirement has to describe its measure the same way:

- the execution mode says whether Prowler evaluates the requirement,
- ``IdGrupoControl`` is the code of a measure of Annex II of the RD, or of one of its
  reinforcements, in a group that exists in the RD,
- ``Marco`` and ``Categoria`` are the block and the group of Annex II that measure
  belongs to.
"""

import json
import os
import re
from typing import Optional

COMPLIANCE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "prowler", "compliance")
)

# <group>.<number>, optionally followed by a reinforcement (.rN). The organisational
# framework has no groups, so its measures are org.<number>.
MEASURE_ID = re.compile(r"(?P<group>org|(?:op|mp)\.[a-z]+)\.\d+(?:\.r\d+)?")
ORGANISATIONAL = "org"

# Blocks and groups of measures of Annex II of Real Decreto 311/2022, as the catalogs
# write them. No catalog files requirements under the organisational framework yet.
MARCOS = {"op": "operacional", "mp": "medidas de protección"}
CATEGORIAS = {
    "op.pl": "planificación",
    "op.acc": "control de acceso",
    "op.exp": "explotación",
    "op.ext": "recursos externos",
    "op.nub": "servicios en la nube",
    "op.cont": "continuidad del servicio",
    "op.mon": "monitorización del sistema",
    "mp.if": "protección de las instalaciones e infraestructuras",
    "mp.per": "gestión del personal",
    "mp.eq": "protección de los equipos",
    "mp.com": "protección de las comunicaciones",
    "mp.si": "protección de los soportes de información",
    "mp.sw": "protección de las aplicaciones informáticas",
    "mp.info": "protección de la información",
    "mp.s": "protección de los servicios",
}


def measure_group(measure_id: str) -> Optional[str]:
    """Return the group of Annex II a measure code belongs to, or None if it is not one.

    The code has to be well formed and its group has to exist in the RD, so a code with
    a mistyped group, such as ``mp.comm.4``, is not a measure.
    """
    measure = MEASURE_ID.fullmatch(measure_id)
    if measure and (
        measure["group"] == ORGANISATIONAL or measure["group"] in CATEGORIAS
    ):
        return measure["group"]
    return None


def load_requirements(provider: str) -> list[dict]:
    """Return the requirements of the ENS catalog of a provider."""
    path = os.path.join(COMPLIANCE_DIR, provider, f"ens_rd2022_{provider}.json")
    with open(path, encoding="utf-8") as catalog:
        return json.load(catalog)["Requirements"]


def execution_mode_mismatches(requirements: list[dict]) -> list[tuple[str, str]]:
    """Return the requirements whose execution mode does not follow from their checks.

    A requirement with checks is evaluated by Prowler and one without them is not, so a
    requirement that gains or loses its checks cannot keep the previous mode.
    """
    return [
        (requirement["Id"], attribute["ModoEjecucion"])
        for requirement in requirements
        for attribute in requirement["Attributes"]
        if attribute["ModoEjecucion"]
        != ("automático" if requirement["Checks"] else "manual")
    ]


def malformed_measure_ids(requirements: list[dict]) -> list[tuple[str, str]]:
    """Return the requirements whose ``IdGrupoControl`` is not the code of a measure."""
    return [
        (requirement["Id"], attribute["IdGrupoControl"])
        for requirement in requirements
        for attribute in requirement["Attributes"]
        if measure_group(attribute["IdGrupoControl"]) is None
    ]


def misfiled_measures(requirements: list[dict]) -> list[tuple[str, str, str]]:
    """Return the requirements filed under a block or a group that is not their measure's."""
    misfiled = []
    for requirement in requirements:
        for attribute in requirement["Attributes"]:
            group = measure_group(attribute["IdGrupoControl"])
            # A code that is not a measure is reported by malformed_measure_ids, and the
            # organisational framework has no groups to be filed under.
            if group is None or group == ORGANISATIONAL:
                continue
            filed_under = (attribute["Marco"], attribute["Categoria"])
            if filed_under != (MARCOS[group.split(".")[0]], CATEGORIAS[group]):
                misfiled.append((requirement["Id"], *filed_under))
    return misfiled
