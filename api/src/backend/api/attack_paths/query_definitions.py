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
        # Custom query for detecting internet-exposed EC2 instances with sensitive S3 access
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

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, ec2)
                YIELD rel AS can_access

                UNWIND nodes(path_s3) + nodes(path_ec2) + nodes(path_role) + nodes(path_assume_role) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_s3, path_ec2, path_role, path_assume_role, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
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
        # Regular Cartography Attack Paths queries
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

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, ec2)
                YIELD rel AS can_access

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
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

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, open)
                YIELD rel AS can_access

                UNWIND nodes(path_open) + nodes(path_sg) + nodes(path_ip) + nodes(path_ipi) + nodes(path_dns) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_open, path_sg, path_ip, path_ipi, path_dns, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
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

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, elb)
                YIELD rel AS can_access

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
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

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, elbv2)
                YIELD rel AS can_access

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-public-ip-resource-lookup",
            name="Identify resources by public IP address",
            description="Given a public IP address, find the related AWS resource and its adjacent node within the selected account.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['Internet'], {id: 'Internet', name: 'Internet'})
                YIELD node AS internet

                CALL () {
                    MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:EC2PrivateIp)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN path, x

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:EC2Instance)-[q]-(y)
                    WHERE x.publicipaddress = $ip
                    RETURN path, x

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:NetworkInterface)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN path, x

                    UNION MATCH path = (aws:AWSAccount {id: $provider_uid})-[r]-(x:ElasticIPAddress)-[q]-(y)
                    WHERE x.public_ip = $ip
                    RETURN path, x
                }

                WITH path, x, internet

                CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {}, x)
                YIELD rel AS can_access

                UNWIND nodes(path) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
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
        # Privilege Escalation Queries (based on pathfinding.cloud research): https://github.com/DataDog/pathfinding.cloud
        AttackPathsQueryDefinition(
            id="aws-iam-privesc-passrole-ec2",
            name="Privilege Escalation: iam:PassRole + ec2:RunInstances",
            description="Detect principals who can launch EC2 instances with privileged IAM roles attached. This allows gaining the permissions of the passed role by accessing the EC2 instance metadata service. This is a new-passrole escalation path (pathfinding.cloud: ec2-001).",
            provider="aws",
            cypher="""
                // Create a single shared virtual EC2 instance node
                CALL apoc.create.vNode(['EC2Instance'], {
                    id: 'potential-ec2-passrole',
                    name: 'New EC2 Instance',
                    description: 'Attacker-controlled EC2 with privileged role'
                })
                YIELD node AS ec2_node

                // Create a single shared virtual escalation outcome node (styled like a finding)
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-passrole-ec2',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH ec2_node, escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Find statements granting iam:PassRole
                MATCH path_passrole = (principal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
                WHERE stmt_passrole.effect = 'Allow'
                    AND any(action IN stmt_passrole.action WHERE
                        toLower(action) = 'iam:passrole'
                        OR toLower(action) = 'iam:*'
                        OR action = '*'
                    )

                // Find statements granting ec2:RunInstances
                MATCH path_ec2 = (principal)--(ec2_policy:AWSPolicy)--(stmt_ec2:AWSPolicyStatement)
                WHERE stmt_ec2.effect = 'Allow'
                    AND any(action IN stmt_ec2.action WHERE
                        toLower(action) = 'ec2:runinstances'
                        OR toLower(action) = 'ec2:*'
                        OR action = '*'
                    )

                // Find roles that trust EC2 service (can be passed to EC2)
                MATCH path_target = (aws)--(target_role:AWSRole)
                WHERE target_role.arn CONTAINS $provider_uid
                    // Check if principal can pass this role
                    AND any(resource IN stmt_passrole.resource WHERE
                        resource = '*'
                        OR target_role.arn CONTAINS resource
                        OR resource CONTAINS target_role.name
                    )

                // Check if target role has elevated permissions (optional, for severity assessment)
                OPTIONAL MATCH (target_role)--(role_policy:AWSPolicy)--(role_stmt:AWSPolicyStatement)
                WHERE role_stmt.effect = 'Allow'
                    AND (
                        any(action IN role_stmt.action WHERE action = '*')
                        OR any(action IN role_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                CALL apoc.create.vRelationship(principal, 'CAN_LAUNCH', {
                    via: 'ec2:RunInstances + iam:PassRole'
                }, ec2_node)
                YIELD rel AS launch_rel

                CALL apoc.create.vRelationship(ec2_node, 'ASSUMES_ROLE', {}, target_role)
                YIELD rel AS assumes_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/ec2-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                UNWIND nodes(path_principal) + nodes(path_passrole) + nodes(path_ec2) + nodes(path_target) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_passrole, path_ec2, path_target,
                       ec2_node, escalation_outcome, launch_rel, assumes_rel, grants_rel,
                       collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-glue-privesc-passrole-dev-endpoint",
            name="Privilege Escalation: Glue Dev Endpoint with PassRole",
            description="Detect principals that can escalate privileges by passing a role to a Glue development endpoint. The attacker creates a dev endpoint with an arbitrary role attached, then accesses those credentials through the endpoint.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-glue',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator (Glue)',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Principal can assume roles (up to 2 hops)
                OPTIONAL MATCH path_assume = (principal)-[:STS_ASSUMEROLE_ALLOW*0..2]->(acting_as:AWSRole)
                WITH escalation_outcome, principal, path_principal, path_assume,
                     CASE WHEN path_assume IS NULL THEN principal ELSE acting_as END AS effective_principal

                // Find iam:PassRole permission
                MATCH path_passrole = (effective_principal)--(passrole_policy:AWSPolicy)--(passrole_stmt:AWSPolicyStatement)
                WHERE passrole_stmt.effect = 'Allow'
                    AND any(action IN passrole_stmt.action WHERE toLower(action) = 'iam:passrole' OR action = '*')

                // Find Glue CreateDevEndpoint permission
                MATCH (effective_principal)--(glue_policy:AWSPolicy)--(glue_stmt:AWSPolicyStatement)
                WHERE glue_stmt.effect = 'Allow'
                    AND any(action IN glue_stmt.action WHERE toLower(action) = 'glue:createdevendpoint' OR action = '*' OR toLower(action) = 'glue:*')

                // Find target role with elevated permissions
                MATCH (aws)--(target_role:AWSRole)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate before creating virtual nodes
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, target_role

                // Create virtual Glue endpoint node (one per unique principal->target pair)
                CALL apoc.create.vNode(['GlueDevEndpoint'], {
                    name: 'New Dev Endpoint',
                    description: 'Glue endpoint with target role attached',
                    id: effective_principal.arn + '->' + target_role.arn
                })
                YIELD node AS glue_endpoint

                CALL apoc.create.vRelationship(effective_principal, 'CREATES_ENDPOINT', {
                    permissions: ['iam:PassRole', 'glue:CreateDevEndpoint'],
                    technique: 'new-passrole'
                }, glue_endpoint)
                YIELD rel AS create_rel

                CALL apoc.create.vRelationship(glue_endpoint, 'RUNS_AS', {}, target_role)
                YIELD rel AS runs_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/glue-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       glue_endpoint, escalation_outcome, create_rel, runs_rel, grants_rel
            """,
            parameters=[],
        ),
    ],
}

_QUERIES_BY_ID: dict[str, AttackPathsQueryDefinition] = {
    definition.id: definition
    for definitions in _QUERY_DEFINITIONS.values()
    for definition in definitions
}
