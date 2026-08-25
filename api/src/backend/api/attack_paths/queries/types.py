from dataclasses import dataclass, field
from enum import Enum


@dataclass(frozen=True)
class AttackPathsQueryOutcomeMeta:
    """Display metadata for an outcome kind.

    `label` and `partial` are properties of the outcome *kind*, not of an
    individual query, so they live here once and every query just references a
    kind. `partial` marks a latent/posture outcome (e.g. inventory) that the UI
    renders as a marker rather than a full realized outcome.
    """

    kind: str
    label: str
    partial: bool = False


class AttackPathsQueryOutcome(Enum):
    """The terminal impact an attack-path query leads to.

    Set per query and exposed by the API so the UI can render the graph's
    terminal outcome node. The taxonomy is shared with Prowler Hub's attack-path
    diagram (whose terminal labels match these values).
    """

    CODE_EXECUTION = AttackPathsQueryOutcomeMeta("code_execution", "Code execution")
    PRIVILEGE_ESCALATION = AttackPathsQueryOutcomeMeta(
        "privilege_escalation", "Privilege escalation"
    )
    PUBLIC_EXPOSURE = AttackPathsQueryOutcomeMeta("public_exposure", "Public exposure")
    RESOURCE_INVENTORY = AttackPathsQueryOutcomeMeta(
        "resource_inventory", "Resource inventory", partial=True
    )


@dataclass
class AttackPathsQueryAttribution:
    """Source attribution for an Attack Path query."""

    text: str
    link: str


@dataclass
class AttackPathsQueryParameterDefinition:
    """
    Metadata describing a parameter that must be provided to an Attack Paths query.
    """

    name: str
    label: str
    data_type: str = "string"
    cast: type = str
    description: str | None = None
    placeholder: str | None = None


@dataclass
class AttackPathsQueryDefinition:
    """
    Immutable representation of an Attack Path query.
    """

    id: str
    name: str
    short_description: str
    description: str
    provider: str
    cypher: str
    attribution: AttackPathsQueryAttribution | None = None
    outcome: AttackPathsQueryOutcome | None = None
    parameters: list[AttackPathsQueryParameterDefinition] = field(default_factory=list)
