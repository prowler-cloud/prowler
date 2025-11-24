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
            name="Identify provisioned RDS instances",
            description="List the selected AWS account alongside the RDS instances it owns.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-rds-unencrypted-storage",
            name="Identify RDS instances without storage encryption",
            description="Find RDS instances with storage encryption disabled within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(rds:RDSInstance)
                WHERE rds.storage_encrypted = false

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-s3-anonymous-access-buckets",
            name="Identify S3 buckets with anonymous access",
            description="Find S3 buckets that allow anonymous access within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(s3:S3Bucket)
                WHERE s3.anonymous_access = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-all-actions",
            name="Identify IAM statements that allow all actions",
            description="Find IAM policy statements that allow all actions via '*' within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = 'Allow'
                    AND any(x IN stmt.action WHERE x = '*')

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-delete-policy",
            name="Identify IAM statements that allow iam:DeletePolicy",
            description="Find IAM policy statements that allow the iam:DeletePolicy action within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = 'Allow'
                    AND any(x IN stmt.action WHERE x = "iam:DeletePolicy")

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-statements-allow-create-actions",
            name="Identify IAM statements that allow create actions",
            description="Find IAM policy statements that allow actions containing 'create' within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = "Allow"
                    AND any(x IN stmt.action WHERE toLower(x) CONTAINS "create")

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-ec2-instances-internet-exposed",
            name="Identify internet-exposed EC2 instances",
            description="Find EC2 instances flagged as exposed to the internet within the selected account.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(instance:EC2Instance {exposed_internet: true})

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                WITH path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
                RETURN path, dpf
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-security-groups-open-internet-facing",
            name="Identify internet-facing resources with open security groups",
            description="Find internet-facing resources associated with security groups that allow inbound access from '0.0.0.0/0'.",
            provider="aws",
            cypher="""
                MATCH (aws:AWSAccount {id: $provider_uid})-[r0]-(open)
                MATCH (open)-[r1:MEMBER_OF_EC2_SECURITY_GROUP]-(sg:EC2SecurityGroup)
                MATCH (sg)-[r2:MEMBER_OF_EC2_SECURITY_GROUP]-(ipi:IpPermissionInbound)
                MATCH (ipi)-[r3]-(ir:IpRange)
                WHERE ir.range = "0.0.0.0/0"
                OPTIONAL MATCH (dns:AWSDNSRecord)-[:DNS_POINTS_TO]->(lb)
                WHERE open.scheme = "internet-facing"

                WITH aws, open, sg, ipi, ir, dns, r0, r1, r2, r3,
                    [node IN [aws, open, sg, ipi, ir, dns] WHERE node IS NOT NULL] AS nodes_path,
                    [relationship IN [r0, r1, r2, r3] WHERE relationship IS NOT NULL] AS relationships_path

                UNWIND nodes_path as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN nodes_path, relationships_path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-classic-elb-internet-exposed",
            name="Identify internet-exposed Classic Load Balancers",
            description="Find Classic Load Balancers exposed to the internet along with their listeners.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elb:LoadBalancer)--(listener:ELBListener)
                WHERE elb.exposed_internet = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-elbv2-internet-exposed",
            name="Identify internet-exposed ELBv2 load balancers",
            description="Find ELBv2 load balancers exposed to the internet along with their listeners.",
            provider="aws",
            cypher="""
                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elbv2:LoadBalancerV2)--(listener:ELBV2Listener)
                WHERE elbv2.exposed_internet = true

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-public-ip-resource-lookup",
            name="Identify resources by public IP address",
            description="Given a public IP address, find the related AWS resource and its adjacent node within the selected account.",
            provider="aws",
            cypher="""
                CALL () {
                    MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:EC2PrivateIp)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN aws, x, r, q, y

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:EC2Instance)-[q]-(y)
                    WHERE x.publicipaddress = $ip
                    RETURN aws, x, r, q, y

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:NetworkInterface)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN aws, x, r, q, y

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:ElasticIPAddress)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN aws, x, r, q, y
                }

                WITH aws, x, r, q, y,
                    [node IN [aws, x, y] WHERE node IS NOT NULL] AS nodes_path,
                    [relationship IN [r, q] WHERE relationship IS NOT NULL] AS relationships_path

                UNWIND nodes_path as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN nodes_path, relationships_path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[
                AttackPathsQueryParameterDefinition(
                    name="ip",
                    label="IP address",
                    description="Public IP address, e.g. 192.0.2.0.",
                    placeholder="192.0.2.0",
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
