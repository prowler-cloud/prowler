from dataclasses import dataclass, field


@dataclass
class AttackPathsQueryAttribution:
    """Source attribution for an Attack Path query."""

    text: str
    link: str


@dataclass
class AttackPathsQueryOutcome:
    """
    Describes the end impact of an attack path (the result of the chain).

    Rendered as a terminal "Outcome" node in the graph so the visualization
    shows not just the resources involved but what an attacker achieves.
    """

    label: str  # Short node label, e.g. "Code execution"
    description: str  # One-line impact, no permission jargon
    severity: str = "high"  # critical|high|medium - drives outcome node color


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
