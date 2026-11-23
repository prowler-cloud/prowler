"""Invariants of the ENS RD 311/2022 catalogs, shared by the tests of each provider.

Every provider keeps its catalog in
``prowler/compliance/<provider>/ens_rd2022_<provider>.json``. The outputs, the API
report and the UI group the requirements by the metadata of the measure they are filed
under, so every requirement has to describe its measure the same way:

- every requirement has attributes, which is where the rest of the invariants look,
- the execution mode says whether Prowler evaluates the requirement,
- ``IdGrupoControl`` is the code of a measure that exists in Annex II of the RD, or of
  one of its reinforcements,
- ``Marco`` and ``Categoria`` are the block and the group of Annex II that measure
  belongs to,
- the requirement id is the code of its measure, the tag of its provider and a suffix.
"""

import json
import os
import re
from typing import Optional

COMPLIANCE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "prowler", "compliance")
)

# <group>.<number>, optionally followed by a reinforcement (.rN). The organisational
# framework has no groups, so its measures are org.<number>. The numbers are one or two
# ASCII digits: no group has more than ten measures, nor a measure more than nine
# reinforcements.
MEASURE_ID = re.compile(
    r"(?P<group>org|(?:op|mp)\.[a-z]+)\.(?P<number>[1-9][0-9]?)"
    r"(?:\.r(?P<reinforcement>[1-9][0-9]?))?"
)
ORGANISATIONAL = "org"

# What follows the measure and the provider in a requirement id: parts of lowercase
# letters and digits separated by dots, such as ``iam.1``.
ID_SUFFIX = r"[a-z0-9]+(?:\.[a-z0-9]+)*"

# Number of reinforcements that Annex II of Real Decreto 311/2022 defines for each of
# its 73 measures, by group and in the order of the RD: op.acc.6, the sixth measure of
# op.acc, has R1 to R9, and op.acc.4 has none.
REINFORCEMENTS = {
    "org": (0, 1, 1, 0),
    "op.pl": (2, 3, 0, 1, 2),
    "op.acc": (1, 2, 3, 0, 7, 9),
    "op.exp": (4, 0, 5, 4, 1, 5, 4, 5, 0, 2),
    "op.ext": (0, 0, 3, 1),
    "op.nub": (2,),
    "op.cont": (0, 2, 0, 1),
    "op.mon": (3, 2, 7),
    "mp.if": (0, 0, 0, 1, 0, 0, 0),
    "mp.per": (1, 1, 0, 0),
    "mp.eq": (1, 1, 2, 2),
    "mp.com": (0, 5, 5, 4),
    "mp.si": (1, 2, 0, 0, 2),
    "mp.sw": (5, 2),
    "mp.info": (0, 0, 5, 1, 0, 2),
    "mp.s": (0, 3, 2, 2),
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

    The code has to be well formed and name a measure of the RD or one of its
    reinforcements, so these are not measures:

    - a code with a mistyped group, such as ``mp.comm.4``,
    - one past the last measure of its group, such as ``op.acc.7``,
    - one past the last reinforcement of its measure, such as ``op.acc.6.r10``.
    """
    code = MEASURE_ID.fullmatch(measure_id)
    if code is None:
        return None
    reinforcements = REINFORCEMENTS.get(code["group"], ())
    number = int(code["number"])
    if number > len(reinforcements):
        return None
    if int(code["reinforcement"] or 0) > reinforcements[number - 1]:
        return None
    return code["group"]


def load_requirements(provider: str) -> list[dict]:
    """Return the requirements of the ENS catalog of a provider."""
    path = os.path.join(COMPLIANCE_DIR, provider, f"ens_rd2022_{provider}.json")
    with open(path, encoding="utf-8") as catalog:
        return json.load(catalog)["Requirements"]


def _attributes(requirement: dict) -> list[dict]:
    """Return the attributes of a requirement, or none if it lacks them."""
    return requirement.get("Attributes") or []


def requirements_without_attributes(requirements: list[dict]) -> list[str]:
    """Return the requirements whose attributes are missing or empty.

    The other invariants read the attributes of each requirement, so they have nothing
    to say about a requirement without them.
    """
    return [
        requirement["Id"]
        for requirement in requirements
        if not _attributes(requirement)
    ]


def execution_mode_mismatches(requirements: list[dict]) -> list[tuple[str, str]]:
    """Return the requirements whose execution mode does not follow from their checks.

    A requirement with checks is evaluated by Prowler and one without them is not, so a
    requirement that gains or loses its checks cannot keep the previous mode.
    """
    return [
        (requirement["Id"], attribute["ModoEjecucion"])
        for requirement in requirements
        for attribute in _attributes(requirement)
        if attribute["ModoEjecucion"]
        != ("automático" if requirement["Checks"] else "manual")
    ]


def malformed_measure_ids(requirements: list[dict]) -> list[tuple[str, str]]:
    """Return the requirements whose ``IdGrupoControl`` is not the code of a measure."""
    return [
        (requirement["Id"], attribute["IdGrupoControl"])
        for requirement in requirements
        for attribute in _attributes(requirement)
        if measure_group(attribute["IdGrupoControl"]) is None
    ]


def misfiled_measures(requirements: list[dict]) -> list[tuple[str, str, str]]:
    """Return the requirements filed under a block or a group that is not their measure's."""
    misfiled = []
    for requirement in requirements:
        for attribute in _attributes(requirement):
            group = measure_group(attribute["IdGrupoControl"])
            # A code that is not a measure is reported by malformed_measure_ids, and the
            # organisational framework has no groups to be filed under.
            if group is None or group == ORGANISATIONAL:
                continue
            filed_under = (attribute["Marco"], attribute["Categoria"])
            if filed_under != (MARCOS[group.split(".")[0]], CATEGORIAS[group]):
                misfiled.append((requirement["Id"], *filed_under))
    return misfiled


def misnamed_requirements(
    requirements: list[dict], provider_tag: str
) -> list[tuple[str, str]]:
    """Return the requirements whose id is not built from their measure and provider.

    A requirement id is ``<IdGrupoControl>.<provider tag>.<suffix>``, and the suffix
    tells apart the requirements of a measure. Each requirement is returned with its
    ``IdGrupoControl``.
    """
    misnamed = []
    for requirement in requirements:
        for attribute in _attributes(requirement):
            prefix = f"{attribute['IdGrupoControl']}.{provider_tag}."
            if not re.fullmatch(re.escape(prefix) + ID_SUFFIX, requirement["Id"]):
                misnamed.append((requirement["Id"], attribute["IdGrupoControl"]))
    return misnamed
