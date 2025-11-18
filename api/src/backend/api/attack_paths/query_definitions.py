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
            id="aws-rds-instances",
            name="What RDS instances are installed",
            description="List every AWS account and the RDS instances it owns.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-rds-unencrypted-storage",
            name="Which RDS instances lack storage encryption",
            description="Find RDS instances where storage encryption is disabled.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)
                WHERE rds.storage_encrypted = false

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-s3-anonymous-access-buckets",
            name="Which S3 buckets allow anonymous access",
            description="Identify S3 buckets with anonymous access enabled.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(s3:S3Bucket)
                WHERE s3.anonymous_access = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-all-actions",
            name="Which IAM statements permit wildcard actions",
            description="Highlight IAM policy statements that allow all actions via '*'.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = 'Allow'
                    AND any(x IN stmt.action WHERE x = '*')

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-delete-policy",
            name="Which IAM statements allow iam:DeletePolicy",
            description="Surface IAM policy statements permitting the iam:DeletePolicy action.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = 'Allow'
                    AND any(x IN stmt.action WHERE x = "iam:DeletePolicy")

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-create-actions",
            name="Which IAM statements allow create actions",
            description="Locate IAM policy statements that allow actions containing 'create'.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = "Allow"
                    AND any(x IN stmt.action WHERE toLower(x) CONTAINS "create")

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-ec2-instances-internet-exposed",
            name="Which EC2 instances are internet exposed",
            description="Identify EC2 instances flagged as exposed to the internet.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(instance:EC2Instance {exposed_internet: true})

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-security-groups-open-internet-facing",
            name="Which internet-facing resources use open security groups",
            description="Detect internet-facing resources associated with security groups that allow inbound access from 0.0.0.0/0.",
            provider="aws",
            cypher="""
                MATCH (aws:AWSAccount {id: $provider_uid})--(open)
                MATCH (open)-[:MEMBER_OF_EC2_SECURITY_GROUP]-(sg:EC2SecurityGroup)
                MATCH (sg)-[:MEMBER_OF_EC2_SECURITY_GROUP]-(ipi:IpPermissionInbound)
                MATCH (ipi)--(ir:IpRange)
                WHERE ir.range = "0.0.0.0/0"
                OPTIONAL MATCH (dns:AWSDNSRecord)-[:DNS_POINTS_TO]->(lb)
                WHERE open.scheme = "internet-facing"

                WITH aws, open, sg, ipi, ir, dns,
                    [node IN [aws, open, sg, ipi, ir, dns] WHERE node IS NOT NULL] AS path

                UNWIND path as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-classic-elb-internet-exposed",
            name="Which Classic Load Balancers are internet exposed",
            description="Reveal Classic Load Balancers that are exposed to the internet along with their listeners.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elb:LoadBalancer)—-(listener:ELBListener)
                WHERE elb.exposed_internet = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-elbv2-internet-exposed",
            name="Which load balancers v2 are internet exposed",
            description="List Application or Network Load Balancers marked as internet exposed.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elbv2:LoadBalancerV2)—-(listener:ELBV2Listener)
                WHERE elbv2.exposed_internet = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)--(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-public-ip-resource-lookup",
            name="Which resources map to a public IP address",
            description="Given a public IP, find the related AWS account, resource, and adjacent node.",
            provider="aws",
            cypher="""
                CALL () {
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(x:EC2PrivateIp)--(y)
                WHERE x.public_ip = $ip
                RETURN aws, x, y

                UNION MATCH path = (aws:AWSAccount {id: $provider_uid})--(x:EC2Instance)--(y)
                WHERE x.publicipaddress = $ip
                RETURN aws, x, y

                UNION MATCH path = (aws:AWSAccount {id: $provider_uid})--(x:NetworkInterface)--(y)
                WHERE x.public_ip = $ip
                RETURN aws, x, y

                UNION MATCH path = (aws:AWSAccount {id: $provider_uid})--(x:ElasticIPAddress)--(y)
                WHERE x.public_ip = $ip
                RETURN aws, x, y
            }

            WITH aws, x, y,
                [node IN [aws, x, y] WHERE node IS NOT NULL] AS path

            UNWIND path as n
            OPTIONAL MATCH (n)--(pf:ProwlerFinding)
            WHERE pf.status = 'FAIL'

            RETURN path, collect(DISTINCT pf) as dpf
            """,
            parameters=[
                AttackPathsQueryParameterDefinition(
                    name="ip",
                    label="IP address",
                    description="Public IP address, e.g. 192.0.2.0.",
                    placeholder="192.0.2.0",
                ),
                AttackPathsQueryParameterDefinition(
                    name="juan",
                    label="juancho",
                    description="arrea",
                    placeholder=4,
                    data_type="integer",
                    cast=int,
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
