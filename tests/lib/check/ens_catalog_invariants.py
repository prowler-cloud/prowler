"""Invariants of the ENS RD 311/2022 catalogs, shared by the tests of each provider.

Every provider keeps its catalog in
``prowler/compliance/<provider>/ens_rd2022_<provider>.json``. The outputs, the API
report and the UI group the requirements by the metadata of the measure they are filed
under, so every requirement has to describe its measure the same way:

- the execution mode says whether Prowler evaluates the requirement,
- ``IdGrupoControl`` is the code of a measure that exists in Annex II of the RD, or of
  one of its reinforcements,
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
MEASURE_ID = re.compile(
    r"(?P<group>org|(?:op|mp)\.[a-z]+)\.(?P<number>[1-9]\d*)(?:\.r[1-9]\d*)?"
)
ORGANISATIONAL = "org"

# Number of measures of each group in the summary table of Annex II of Real Decreto
# 311/2022, 73 in all. The reinforcements are not listed: the RD defines them in the
# text of each measure.
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

    The code has to be well formed and name a measure of the RD, so neither a code with
    a mistyped group, such as ``mp.comm.4``, nor one past the last measure of its
    group, such as ``op.acc.7``, is a measure.
    """
    measure = MEASURE_ID.fullmatch(measure_id)
    if measure and int(measure["number"]) <= MEASURES.get(measure["group"], 0):
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
