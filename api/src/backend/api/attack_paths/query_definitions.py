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
        # =====================================================================
        # Privilege Escalation Queries (based on pathfinding.cloud research)
        # Reference: https://github.com/DataDog/pathfinding.cloud
        # =====================================================================
        AttackPathsQueryDefinition(
            id="aws-iam-privesc-create-policy-version",
            name="Privilege Escalation: iam:CreatePolicyVersion",
            description="Detect principals with iam:CreatePolicyVersion permission who can modify policies attached to themselves or others, enabling privilege escalation by creating a new policy version with elevated permissions. This is a self-escalation path (pathfinding.cloud: iam-001).",
            provider="aws",
            cypher="""
                // Create a single shared virtual escalation outcome node (styled like a finding)
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-createpolicyversion',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals with iam:CreatePolicyVersion permission
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Find policies attached to the principal
                MATCH path_attached = (principal)--(attached_policy:AWSPolicy)
                WHERE attached_policy.type = 'Customer Managed'

                // Find policy statements that grant iam:CreatePolicyVersion
                MATCH path_perms = (principal)--(perms_policy:AWSPolicy)--(stmt:AWSPolicyStatement)
                WHERE stmt.effect = 'Allow'
                    AND (
                        any(action IN stmt.action WHERE
                            toLower(action) = 'iam:createpolicyversion'
                            OR toLower(action) = 'iam:*'
                            OR action = '*'
                        )
                    )
                    // Check resource constraints - can they modify the attached policy?
                    AND (
                        any(resource IN stmt.resource WHERE
                            resource = '*'
                            OR attached_policy.arn CONTAINS resource
                            OR resource CONTAINS attached_policy.name
                        )
                    )

                // Deduplicate before creating virtual relationships
                WITH DISTINCT escalation_outcome, aws, principal, attached_policy

                CALL apoc.create.vRelationship(principal, 'CAN_ESCALATE_TO', {
                    via: 'iam:CreatePolicyVersion',
                    target_policy: attached_policy.arn,
                    reference: 'https://pathfinding.cloud/paths/iam-001'
                }, escalation_outcome)
                YIELD rel AS escalation_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_attached = (principal)--(attached_policy)

                UNWIND nodes(path_principal) + nodes(path_attached) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_attached,
                       escalation_outcome, escalation_rel,
                       collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-privesc-attach-role-policy-assume-role",
            name="Privilege Escalation: iam:AttachRolePolicy + sts:AssumeRole",
            description="Detect principals who can both attach policies to roles AND assume those roles. This two-step attack allows modifying a role's permissions then assuming it to gain elevated access. This is a principal-access escalation path (pathfinding.cloud: iam-014).",
            provider="aws",
            cypher="""
                // Create a virtual escalation outcome node (styled like a finding)
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS admin_outcome

                WITH admin_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Find statements granting iam:AttachRolePolicy
                MATCH path_attach = (principal)--(attach_policy:AWSPolicy)--(stmt_attach:AWSPolicyStatement)
                WHERE stmt_attach.effect = 'Allow'
                    AND any(action IN stmt_attach.action WHERE
                        toLower(action) = 'iam:attachrolepolicy'
                        OR toLower(action) = 'iam:*'
                        OR action = '*'
                    )

                // Find statements granting sts:AssumeRole
                MATCH path_assume = (principal)--(assume_policy:AWSPolicy)--(stmt_assume:AWSPolicyStatement)
                WHERE stmt_assume.effect = 'Allow'
                    AND any(action IN stmt_assume.action WHERE
                        toLower(action) = 'sts:assumerole'
                        OR toLower(action) = 'sts:*'
                        OR action = '*'
                    )

                // Find target roles that the principal can both modify AND assume
                MATCH path_target = (aws)--(target_role:AWSRole)
                WHERE target_role.arn CONTAINS $provider_uid
                    // Can attach policy to this role
                    AND any(resource IN stmt_attach.resource WHERE
                        resource = '*'
                        OR target_role.arn CONTAINS resource
                        OR resource CONTAINS target_role.name
                    )
                    // Can assume this role
                    AND any(resource IN stmt_assume.resource WHERE
                        resource = '*'
                        OR target_role.arn CONTAINS resource
                        OR resource CONTAINS target_role.name
                    )

                // Deduplicate before creating virtual relationships
                WITH DISTINCT admin_outcome, aws, principal, target_role

                // Create virtual relationships showing the attack path
                CALL apoc.create.vRelationship(principal, 'CAN_MODIFY', {
                    via: 'iam:AttachRolePolicy'
                }, target_role)
                YIELD rel AS modify_rel

                CALL apoc.create.vRelationship(target_role, 'LEADS_TO', {
                    technique: 'iam:AttachRolePolicy + sts:AssumeRole',
                    via: 'sts:AssumeRole',
                    reference: 'https://pathfinding.cloud/paths/iam-014'
                }, admin_outcome)
                YIELD rel AS escalation_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                UNWIND nodes(path_principal) + nodes(path_target) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_target,
                       admin_outcome, modify_rel, escalation_rel,
                       collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
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
            id="aws-iam-privesc-passrole-lambda",
            name="Privilege Escalation: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
            description="Detect principals who can create Lambda functions with privileged IAM roles and invoke them. This allows executing code with the permissions of the passed role. This is a new-passrole escalation path (pathfinding.cloud: lambda-001).",
            provider="aws",
            cypher="""
                // Create a single shared virtual escalation outcome node (styled like a finding)
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-passrole-lambda',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

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

                // Find statements granting lambda:CreateFunction
                MATCH path_create = (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
                WHERE stmt_create.effect = 'Allow'
                    AND any(action IN stmt_create.action WHERE
                        toLower(action) = 'lambda:createfunction'
                        OR toLower(action) = 'lambda:*'
                        OR action = '*'
                    )

                // Find statements granting lambda:InvokeFunction
                MATCH path_invoke = (principal)--(invoke_policy:AWSPolicy)--(stmt_invoke:AWSPolicyStatement)
                WHERE stmt_invoke.effect = 'Allow'
                    AND any(action IN stmt_invoke.action WHERE
                        toLower(action) = 'lambda:invokefunction'
                        OR toLower(action) = 'lambda:*'
                        OR action = '*'
                    )

                // Find target roles with elevated permissions that could be passed
                MATCH (aws)--(target_role:AWSRole)--(role_policy:AWSPolicy)--(role_stmt:AWSPolicyStatement)
                WHERE role_stmt.effect = 'Allow'
                    AND (
                        any(action IN role_stmt.action WHERE action = '*')
                        OR any(action IN role_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate per (principal, target_role) pair
                WITH DISTINCT escalation_outcome, aws, principal, target_role

                // Group by principal, collect target_roles
                WITH escalation_outcome, aws, principal,
                     collect(DISTINCT target_role) AS target_roles,
                     count(DISTINCT target_role) AS target_count

                // Create single virtual Lambda function node per principal
                CALL apoc.create.vNode(['LambdaFunction'], {
                    name: 'New Lambda Function',
                    description: toString(target_count) + ' admin role(s) can be passed',
                    id: principal.arn,
                    target_role_count: target_count
                })
                YIELD node AS lambda_node

                CALL apoc.create.vRelationship(principal, 'CAN_CREATE_AND_INVOKE', {
                    via: 'lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole'
                }, lambda_node)
                YIELD rel AS create_rel

                // UNWIND target_roles to show which roles can be passed
                UNWIND target_roles AS target_role

                CALL apoc.create.vRelationship(lambda_node, 'PASSES_ROLE', {}, target_role)
                YIELD rel AS pass_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/lambda-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       lambda_node, escalation_outcome, create_rel, pass_rel, grants_rel, target_count
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-privesc-role-chain",
            name="Privilege Escalation: Role Assumption Chains to Admin",
            description="Detect multi-hop role assumption chains where a principal can reach an administrative role through one or more intermediate role assumptions. This traces STS_ASSUMEROLE_ALLOW relationships to find paths to privileged roles.",
            provider="aws",
            cypher="""
                // Create a single shared virtual escalation outcome node (styled like a finding)
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-rolechain',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Find role assumption chains (1-5 hops) to roles with elevated permissions
                MATCH path_chain = (principal)-[:STS_ASSUMEROLE_ALLOW*1..5]->(target_role:AWSRole)

                // Target role must have administrative permissions
                MATCH path_admin = (target_role)--(admin_policy:AWSPolicy)--(admin_stmt:AWSPolicyStatement)
                WHERE admin_stmt.effect = 'Allow'
                    AND (
                        any(action IN admin_stmt.action WHERE action = '*')
                        OR any(action IN admin_stmt.action WHERE toLower(action) = 'iam:*')
                        OR any(action IN admin_stmt.action WHERE toLower(action) CONTAINS 'admin')
                    )

                // Deduplicate and calculate chain length before creating virtual relationships
                WITH DISTINCT escalation_outcome, aws, principal, target_role, path_chain,
                     length(path_chain) as chain_length,
                     [node in nodes(path_chain) | node.name] as chain_nodes

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ADMIN', {
                    hops: chain_length,
                    technique: 'sts:AssumeRole chain (' + toString(chain_length) + ' hops)',
                    reference: 'https://pathfinding.cloud/paths/sts-001'
                }, escalation_outcome)
                YIELD rel AS admin_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)

                RETURN path_principal, path_chain,
                       escalation_outcome, admin_rel,
                       chain_length, chain_nodes
                ORDER BY chain_length ASC
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-ecs-privesc-passrole-task",
            name="Privilege Escalation: ECS Task Definition with PassRole",
            description="Detect principals that can escalate privileges by passing a role to an ECS task definition and creating a service. The attacker can register a task definition with an arbitrary role, then access those role credentials from the running container.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-ecs',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator (ECS)',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Principal can assume roles (up to 2 hops for flexibility)
                OPTIONAL MATCH path_assume = (principal)-[:STS_ASSUMEROLE_ALLOW*0..2]->(acting_as:AWSRole)
                WITH escalation_outcome, aws, principal, path_principal, path_assume,
                     CASE WHEN path_assume IS NULL THEN principal ELSE acting_as END AS effective_principal

                // Find iam:PassRole permission
                MATCH path_passrole = (effective_principal)--(passrole_policy:AWSPolicy)--(passrole_stmt:AWSPolicyStatement)
                WHERE passrole_stmt.effect = 'Allow'
                    AND any(action IN passrole_stmt.action WHERE toLower(action) = 'iam:passrole' OR action = '*')

                // Find ECS task definition permissions
                MATCH (effective_principal)--(ecs_policy:AWSPolicy)--(ecs_stmt:AWSPolicyStatement)
                WHERE ecs_stmt.effect = 'Allow'
                    AND (
                        any(action IN ecs_stmt.action WHERE toLower(action) = 'ecs:registertaskdefinition' OR action = '*' OR toLower(action) = 'ecs:*')
                    )
                    AND (
                        any(action IN ecs_stmt.action WHERE toLower(action) = 'ecs:createservice' OR toLower(action) = 'ecs:runtask' OR action = '*' OR toLower(action) = 'ecs:*')
                    )

                // Find target roles with elevated permissions that could be passed
                MATCH (aws)--(target_role:AWSRole)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate per (principal, target_role) pair
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, target_role

                // Group by principal, collect target_roles
                WITH escalation_outcome, aws, principal, effective_principal,
                     collect(DISTINCT target_role) AS target_roles,
                     count(DISTINCT target_role) AS target_count

                // Create single virtual ECS task node per principal
                CALL apoc.create.vNode(['ECSTask'], {
                    name: 'New Task Definition',
                    description: toString(target_count) + ' admin role(s) can be passed',
                    id: effective_principal.arn,
                    target_role_count: target_count
                })
                YIELD node AS ecs_task

                CALL apoc.create.vRelationship(effective_principal, 'CREATES_TASK', {
                    permissions: ['iam:PassRole', 'ecs:RegisterTaskDefinition', 'ecs:CreateService'],
                    technique: 'new-passrole'
                }, ecs_task)
                YIELD rel AS create_rel

                // UNWIND target_roles to show which roles can be passed
                UNWIND target_roles AS target_role

                CALL apoc.create.vRelationship(ecs_task, 'PASSES_ROLE', {}, target_role)
                YIELD rel AS pass_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/ecs-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       ecs_task, escalation_outcome, create_rel, pass_rel, grants_rel, target_count
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-ssm-privesc-start-session",
            name="Privilege Escalation: SSM Start Session to EC2 Role",
            description="Detect principals that can escalate privileges by using SSM StartSession to access an EC2 instance and inherit its IAM role credentials. This is an existing-passrole technique where the role is already attached to the instance.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-ssm',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator (SSM)',
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

                // Find ssm:StartSession permission
                MATCH (effective_principal)--(ssm_policy:AWSPolicy)--(ssm_stmt:AWSPolicyStatement)
                WHERE ssm_stmt.effect = 'Allow'
                    AND any(action IN ssm_stmt.action WHERE toLower(action) = 'ssm:startsession' OR action = '*' OR toLower(action) = 'ssm:*')

                // Find EC2 instances with instance profiles
                MATCH (aws)--(instance:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(instance_role:AWSRole)

                // Instance role should have elevated permissions
                MATCH (instance_role)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                        OR any(action IN target_stmt.action WHERE toLower(action) CONTAINS 'admin')
                    )

                // Deduplicate before creating virtual relationships
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, instance, instance_role

                CALL apoc.create.vRelationship(effective_principal, 'SSM_ACCESS', {
                    permissions: ['ssm:StartSession'],
                    technique: 'existing-passrole'
                }, instance)
                YIELD rel AS ssm_rel

                CALL apoc.create.vRelationship(instance_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/ssm-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_ec2 = (aws)--(instance)-[:STS_ASSUMEROLE_ALLOW]->(instance_role)

                RETURN path_principal, path_ec2,
                       escalation_outcome, ssm_rel, grants_rel
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
                WITH escalation_outcome, aws, principal, path_principal, path_assume,
                     CASE WHEN path_assume IS NULL THEN principal ELSE acting_as END AS effective_principal

                // Find iam:PassRole permission
                MATCH path_passrole = (effective_principal)--(passrole_policy:AWSPolicy)--(passrole_stmt:AWSPolicyStatement)
                WHERE passrole_stmt.effect = 'Allow'
                    AND any(action IN passrole_stmt.action WHERE toLower(action) = 'iam:passrole' OR action = '*')

                // Find Glue CreateDevEndpoint permission
                MATCH (effective_principal)--(glue_policy:AWSPolicy)--(glue_stmt:AWSPolicyStatement)
                WHERE glue_stmt.effect = 'Allow'
                    AND any(action IN glue_stmt.action WHERE toLower(action) = 'glue:createdevendpoint' OR action = '*' OR toLower(action) = 'glue:*')

                // Find target roles with elevated permissions that could be passed
                MATCH (aws)--(target_role:AWSRole)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate per (principal, target_role) pair
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, target_role

                // Group by principal, collect target_roles
                WITH escalation_outcome, aws, principal, effective_principal,
                     collect(DISTINCT target_role) AS target_roles,
                     count(DISTINCT target_role) AS target_count

                // Create single virtual Glue endpoint node per principal
                CALL apoc.create.vNode(['GlueDevEndpoint'], {
                    name: 'New Dev Endpoint',
                    description: toString(target_count) + ' admin role(s) can be passed',
                    id: effective_principal.arn,
                    target_role_count: target_count
                })
                YIELD node AS glue_endpoint

                CALL apoc.create.vRelationship(effective_principal, 'CREATES_ENDPOINT', {
                    permissions: ['iam:PassRole', 'glue:CreateDevEndpoint'],
                    technique: 'new-passrole'
                }, glue_endpoint)
                YIELD rel AS create_rel

                // UNWIND target_roles to show which roles can be passed
                UNWIND target_roles AS target_role

                CALL apoc.create.vRelationship(glue_endpoint, 'PASSES_ROLE', {}, target_role)
                YIELD rel AS pass_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/glue-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       glue_endpoint, escalation_outcome, create_rel, pass_rel, grants_rel, target_count
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-bedrock-privesc-passrole-code-interpreter",
            name="Privilege Escalation: Bedrock Code Interpreter with PassRole",
            description="Detect principals that can escalate privileges by passing a role to a Bedrock AgentCore Code Interpreter. The attacker creates a code interpreter with an arbitrary role, then invokes it to execute code with those credentials.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-bedrock',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator (Bedrock)',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Principal can assume roles (up to 2 hops)
                OPTIONAL MATCH path_assume = (principal)-[:STS_ASSUMEROLE_ALLOW*0..2]->(acting_as:AWSRole)
                WITH escalation_outcome, aws, principal, path_principal, path_assume,
                     CASE WHEN path_assume IS NULL THEN principal ELSE acting_as END AS effective_principal

                // Find iam:PassRole permission
                MATCH path_passrole = (effective_principal)--(passrole_policy:AWSPolicy)--(passrole_stmt:AWSPolicyStatement)
                WHERE passrole_stmt.effect = 'Allow'
                    AND any(action IN passrole_stmt.action WHERE toLower(action) = 'iam:passrole' OR action = '*')

                // Find Bedrock AgentCore permissions
                MATCH (effective_principal)--(bedrock_policy:AWSPolicy)--(bedrock_stmt:AWSPolicyStatement)
                WHERE bedrock_stmt.effect = 'Allow'
                    AND (
                        any(action IN bedrock_stmt.action WHERE toLower(action) = 'bedrock-agentcore:createcodeinterpreter' OR action = '*' OR toLower(action) = 'bedrock-agentcore:*')
                    )
                    AND (
                        any(action IN bedrock_stmt.action WHERE toLower(action) = 'bedrock-agentcore:startsession' OR action = '*' OR toLower(action) = 'bedrock-agentcore:*')
                    )
                    AND (
                        any(action IN bedrock_stmt.action WHERE toLower(action) = 'bedrock-agentcore:invoke' OR action = '*' OR toLower(action) = 'bedrock-agentcore:*')
                    )

                // Find target roles with elevated permissions that could be passed
                MATCH (aws)--(target_role:AWSRole)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate per (principal, target_role) pair
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, target_role

                // Group by principal, collect target_roles
                WITH escalation_outcome, aws, principal, effective_principal,
                     collect(DISTINCT target_role) AS target_roles,
                     count(DISTINCT target_role) AS target_count

                // Create single virtual Bedrock node per principal
                CALL apoc.create.vNode(['BedrockCodeInterpreter'], {
                    name: 'New Code Interpreter',
                    description: toString(target_count) + ' admin role(s) can be passed',
                    id: effective_principal.arn,
                    target_role_count: target_count
                })
                YIELD node AS bedrock_agent

                CALL apoc.create.vRelationship(effective_principal, 'CREATES_INTERPRETER', {
                    permissions: ['iam:PassRole', 'bedrock-agentcore:CreateCodeInterpreter', 'bedrock-agentcore:StartSession', 'bedrock-agentcore:Invoke'],
                    technique: 'new-passrole'
                }, bedrock_agent)
                YIELD rel AS create_rel

                // UNWIND target_roles to show which roles can be passed
                UNWIND target_roles AS target_role

                CALL apoc.create.vRelationship(bedrock_agent, 'PASSES_ROLE', {}, target_role)
                YIELD rel AS pass_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/bedrock-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       bedrock_agent, escalation_outcome, create_rel, pass_rel, grants_rel, target_count
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-cloudformation-privesc-passrole-create-stack",
            name="Privilege Escalation: CloudFormation Stack with PassRole",
            description="Detect principals that can escalate privileges by passing a role to a CloudFormation stack. The attacker creates a stack with an arbitrary role, allowing CloudFormation to perform actions as that role when creating resources.",
            provider="aws",
            cypher="""
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'effective-administrator-cfn',
                    check_title: 'Privilege Escalation',
                    name: 'Effective Administrator (CloudFormation)',
                    status: 'FAIL',
                    severity: 'critical'
                })
                YIELD node AS escalation_outcome

                WITH escalation_outcome

                // Find principals in the account
                MATCH path_principal = (aws:AWSAccount {id: $provider_uid})--(principal:AWSPrincipal)

                // Principal can assume roles (up to 2 hops)
                OPTIONAL MATCH path_assume = (principal)-[:STS_ASSUMEROLE_ALLOW*0..2]->(acting_as:AWSRole)
                WITH escalation_outcome, aws, principal, path_principal, path_assume,
                     CASE WHEN path_assume IS NULL THEN principal ELSE acting_as END AS effective_principal

                // Find iam:PassRole permission
                MATCH path_passrole = (effective_principal)--(passrole_policy:AWSPolicy)--(passrole_stmt:AWSPolicyStatement)
                WHERE passrole_stmt.effect = 'Allow'
                    AND any(action IN passrole_stmt.action WHERE toLower(action) = 'iam:passrole' OR action = '*')

                // Find CloudFormation CreateStack permission
                MATCH (effective_principal)--(cfn_policy:AWSPolicy)--(cfn_stmt:AWSPolicyStatement)
                WHERE cfn_stmt.effect = 'Allow'
                    AND any(action IN cfn_stmt.action WHERE toLower(action) = 'cloudformation:createstack' OR action = '*' OR toLower(action) = 'cloudformation:*')

                // Find target roles with elevated permissions that could be passed
                MATCH (aws)--(target_role:AWSRole)--(target_policy:AWSPolicy)--(target_stmt:AWSPolicyStatement)
                WHERE target_stmt.effect = 'Allow'
                    AND (
                        any(action IN target_stmt.action WHERE action = '*')
                        OR any(action IN target_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Deduplicate per (principal, target_role) pair
                WITH DISTINCT escalation_outcome, aws, principal, effective_principal, target_role

                // Group by principal, collect target_roles
                WITH escalation_outcome, aws, principal, effective_principal,
                     collect(DISTINCT target_role) AS target_roles,
                     count(DISTINCT target_role) AS target_count

                // Create single virtual CloudFormation stack node per principal
                CALL apoc.create.vNode(['CloudFormationStack'], {
                    name: 'New Stack',
                    description: toString(target_count) + ' admin role(s) can be passed',
                    id: effective_principal.arn,
                    target_role_count: target_count
                })
                YIELD node AS cfn_stack

                CALL apoc.create.vRelationship(effective_principal, 'CREATES_STACK', {
                    permissions: ['iam:PassRole', 'cloudformation:CreateStack'],
                    technique: 'new-passrole'
                }, cfn_stack)
                YIELD rel AS create_rel

                // UNWIND target_roles to show which roles can be passed
                UNWIND target_roles AS target_role

                CALL apoc.create.vRelationship(cfn_stack, 'PASSES_ROLE', {}, target_role)
                YIELD rel AS pass_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {
                    reference: 'https://pathfinding.cloud/paths/cloudformation-001'
                }, escalation_outcome)
                YIELD rel AS grants_rel

                // Re-match paths for visualization
                MATCH path_principal = (aws)--(principal)
                MATCH path_target = (aws)--(target_role)

                RETURN path_principal, path_target,
                       cfn_stack, escalation_outcome, create_rel, pass_rel, grants_rel, target_count
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
