from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class AttackPathParameterDefinition:
    """Metadata describing a parameter that must be provided to an attack path query."""

    name: str
    label: str
    type: str = "string"
    required: bool = True
    description: str | None = None
    placeholder: str | None = None


@dataclass(frozen=True, slots=True)
class AttackPathQueryDefinition:
    """Immutable representation of an attack path query."""

    id: str
    name: str
    description: str
    provider: str
    cypher: str
    parameters: list[AttackPathParameterDefinition] = field(default_factory=list)
    max_results: int = 100


# Placeholder definitions that will be expanded with additional queries.
_QUERY_DEFINITIONS: list[AttackPathQueryDefinition] = [
    AttackPathQueryDefinition(
        id="aws-ec2-instance-security-groups",
        name="EC2 instance security group exposure",
        description=(
            "Explore the security groups and network interfaces attached to a specific "
            "EC2 instance to understand its exposure surface."
        ),
        provider="aws",
        cypher=(
            "MATCH path=(instance:AwsEc2Instance {id: $instance_id})"
            "-[:NETWORK_INTERFACE|MEMBER_OF_SECURITY_GROUP*1..2]->(target) "
            "RETURN nodes(path) AS nodes, relationships(path) AS relationships "
            "LIMIT $limit"
        ),
        parameters=[
            AttackPathParameterDefinition(
                name="instance_id",
                label="EC2 instance ID",
                description="Full identifier of the EC2 instance, e.g. i-0abc123456789def0.",
                placeholder="i-0abc123456789def0",
            ),
        ],
    ),
    AttackPathQueryDefinition(
        id="aws-s3-bucket-access",
        name="S3 bucket access graph",
        description=(
            "Show identities that have direct relationships with a given S3 bucket."
        ),
        provider="aws",
        cypher=(
            "MATCH path=(bucket:AwsS3Bucket {name: $bucket_name})"
            "<-[:RESOURCE]-(:AwsAccount)-[:RESOURCE]->(identity) "
            "RETURN nodes(path) AS nodes, relationships(path) AS relationships "
            "LIMIT $limit"
        ),
        parameters=[
            AttackPathParameterDefinition(
                name="bucket_name",
                label="S3 bucket name",
                description="Case-sensitive bucket name, e.g. production-logs.",
                placeholder="production-logs",
            ),
        ],
    ),
]

_QUERIES_BY_ID: dict[str, AttackPathQueryDefinition] = {
    definition.id: definition for definition in _QUERY_DEFINITIONS
}


def get_queries_for_provider(provider: str) -> list[AttackPathQueryDefinition]:
    """Return the queries supported for the given provider."""

    return [
        definition
        for definition in _QUERY_DEFINITIONS
        if definition.provider == provider
    ]


def get_query_by_id(query_id: str) -> AttackPathQueryDefinition | None:
    """Retrieve an attack path query definition by ID, if it exists."""

    return _QUERIES_BY_ID.get(query_id)
