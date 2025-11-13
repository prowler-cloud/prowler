from dataclasses import dataclass, field


# Dataclases for handling API's Attack Path query definitions and their parameters
@dataclass
class AttackPathsQueryParameterDefinition:
    """
    Metadata describing a parameter that must be provided to an Attack Paths query.
    """

    name: str
    label: str
    data_type: str = "string"
    description: str | None = None
    placeholder: str | None = None


@dataclass
class AttackPathsQueryDefinition:
    """
    Immutable representation of an Attack Path query.
    """

    id: str
    name: str
    description: str
    provider: str
    cypher: str
    parameters: list[AttackPathsQueryParameterDefinition] = field(default_factory=list)


# Accessor functions for API's Attack Paths query definitions
def get_queries_for_provider(provider: str) -> list[AttackPathsQueryDefinition]:
    return _QUERY_DEFINITIONS.get(provider, [])


def get_query_by_id(query_id: str) -> AttackPathsQueryDefinition | None:
    return _QUERIES_BY_ID.get(query_id)


# API's Attack Paths query definitions
_QUERY_DEFINITIONS: dict[str, list[AttackPathsQueryDefinition]] = {
    "aws": [
        AttackPathsQueryDefinition(
            id="aws-s3-buckets",
            name="S3 buckets",
            description=("Explore all S3 buckets in the AWS account "),
            provider="aws",
            cypher=(
                "MATCH (a:AWSAccount {id: $provider_uid})-[r]-(s:S3Bucket) "
                "RETURN a, s, r"
            ),
            parameters=[],
        ),
        AttackPathsQueryDefinition(
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
            ),
            parameters=[
                AttackPathsQueryParameterDefinition(
                    name="instance_id",
                    label="EC2 instance ID",
                    description="Full identifier of the EC2 instance, e.g. i-0abc123456789def0.",
                    placeholder="i-0abc123456789def0",
                ),
            ],
        ),
        AttackPathsQueryDefinition(
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
            ),
            parameters=[
                AttackPathsQueryParameterDefinition(
                    name="bucket_name",
                    label="S3 bucket name",
                    description="Case-sensitive bucket name, e.g. production-logs.",
                    placeholder="production-logs",
                ),
            ],
        ),
    ],
}

_QUERIES_BY_ID: dict[str, AttackPathsQueryDefinition] = {
    definition.id: definition
    for definitions in _QUERY_DEFINITIONS.values()
    for definition in definitions
}
