from dataclasses import dataclass, field


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
    parameters: list[AttackPathsQueryParameterDefinition] = field(default_factory=list)
