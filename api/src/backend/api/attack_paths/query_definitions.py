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
            id="aws-internet-exposed-ec2-sensitive-s3-access",
            name="Identify internet-exposed EC2 instances with sensitive S3 access",
            description="Detect EC2 instances with SSH exposed to the internet that can assume higher-privileged roles to read tagged sensitive S3 buckets despite bucket-level public access blocks.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                MATCH path_s3 = (aws:AWSAccount {id: $provider_uid})--(s3:S3Bucket)--(t:AWSTag)
                WHERE toLower(t.key) = toLower($tag_key) AND toLower(t.value) = toLower($tag_value)

                MATCH path_ec2 = (aws)--(ec2:EC2Instance)--(sg:EC2SecurityGroup)--(ipi:IpPermissionInbound)
                WHERE ec2.exposed_internet = true
                    AND ipi.toport = 22

                MATCH path_role = (r:AWSRole)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE ANY(x IN stmt.resource WHERE x CONTAINS s3.name)
                    AND ANY(x IN stmt.action WHERE toLower(x) =~ 's3:(listbucket|getobject).*')

                MATCH path_assume_role = (ec2)-[p:STS_ASSUMEROLE_ALLOW*1..9]-(r:AWSRole)

                CALL apoc.create.vRelationship(ec2, 'IS_ACCESIBLE_FROM', {}, internet)
                YIELD rel AS is_accessible_from

                UNWIND nodes(path_s3) + nodes(path_ec2) + nodes(path_role) + nodes(path_assume_role) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_s3, path_ec2, path_role, path_assume_role, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, is_accessible_from
            """,
            parameters=[
                AttackPathsQueryParameterDefinition(
                    name="tag_key",
                    label="Tag key",
                    description="Tag key to filter the S3 bucket, e.g. DataClassification.",
                    placeholder="DataClassification",
                ),
                AttackPathsQueryParameterDefinition(
                    name="tag_value",
                    label="Tag value",
                    description="Tag value to filter the S3 bucket, e.g. Sensitive.",
                    placeholder="Sensitive",
                ),
            ],
        ),
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
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                MATCH path = (aws:AWSAccount {id: $provider_uid})--(ec2:EC2Instance)
                WHERE ec2.exposed_internet = true

                CALL apoc.create.vRelationship(ec2, 'IS_ACCESIBLE_FROM', {}, internet)
                YIELD rel AS is_accessible_from

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, is_accessible_from
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-security-groups-open-internet-facing",
            name="Identify internet-facing resources with open security groups",
            description="Find internet-facing resources associated with security groups that allow inbound access from '0.0.0.0/0'.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                MATCH path_open = (aws:AWSAccount {id: $provider_uid})-[r0]-(open)
                MATCH path_sg = (open)-[r1:MEMBER_OF_EC2_SECURITY_GROUP]-(sg:EC2SecurityGroup)
                MATCH path_ip = (sg)-[r2:MEMBER_OF_EC2_SECURITY_GROUP]-(ipi:IpPermissionInbound)
                MATCH path_ipi = (ipi)-[r3]-(ir:IpRange)
                WHERE ir.range = "0.0.0.0/0"
                OPTIONAL MATCH path_dns = (dns:AWSDNSRecord)-[:DNS_POINTS_TO]->(lb)
                WHERE open.scheme = 'internet-facing'

                CALL apoc.create.vRelationship(open, 'IS_ACCESIBLE_FROM', {}, internet)
                YIELD rel AS is_accessible_from

                UNWIND nodes(path_open) + nodes(path_sg) + nodes(path_ip) + nodes(path_ipi) + nodes(path_dns) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_open, path_sg, path_ip, path_ipi, path_dns, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, is_accessible_from
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-classic-elb-internet-exposed",
            name="Identify internet-exposed Classic Load Balancers",
            description="Find Classic Load Balancers exposed to the internet along with their listeners.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elb:LoadBalancer)--(listener:ELBListener)
                WHERE elb.exposed_internet = true

                CALL apoc.create.vRelationship(elb, 'IS_ACCESIBLE_FROM', {}, internet)
                YIELD rel AS is_accessible_from

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, is_accessible_from
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-elbv2-internet-exposed",
            name="Identify internet-exposed ELBv2 load balancers",
            description="Find ELBv2 load balancers exposed to the internet along with their listeners.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                MATCH path = (aws:AWSAccount {id: $provider_uid})--(elbv2:LoadBalancerV2)--(listener:ELBV2Listener)
                WHERE elbv2.exposed_internet = true

                CALL apoc.create.vRelationship(elbv2, 'IS_ACCESIBLE_FROM', {}, internet)
                YIELD rel AS is_accessible_from

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, is_accessible_from
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
                    RETURN path

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:EC2Instance)-[q]-(y)
                    WHERE x.publicipaddress = $ip
                    RETURN path

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:NetworkInterface)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN path

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:ElasticIPAddress)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN path
                }

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
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
