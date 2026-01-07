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

                // Create a virtual "Escalation" node to visualize the attack outcome
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'privesc-' + principal.arn,
                    name: 'Effective Administrator',
                    technique: 'iam:CreatePolicyVersion',
                    severity: 'CRITICAL',
                    reference: 'https://pathfinding.cloud/paths/iam-001'
                })
                YIELD node AS escalation_outcome

                CALL apoc.create.vRelationship(principal, 'CAN_ESCALATE_TO', {
                    via: 'iam:CreatePolicyVersion',
                    target_policy: attached_policy.arn
                }, escalation_outcome)
                YIELD rel AS escalation_rel

                UNWIND nodes(path_principal) + nodes(path_attached) + nodes(path_perms) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_attached, path_perms,
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

                // Create visualization of the escalation path
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'privesc-' + principal.arn + '-via-' + target_role.name,
                    name: 'Effective Administrator',
                    technique: 'iam:AttachRolePolicy + sts:AssumeRole',
                    severity: 'CRITICAL',
                    reference: 'https://pathfinding.cloud/paths/iam-014'
                })
                YIELD node AS escalation_outcome

                CALL apoc.create.vRelationship(principal, 'CAN_MODIFY', {
                    via: 'iam:AttachRolePolicy'
                }, target_role)
                YIELD rel AS modify_rel

                CALL apoc.create.vRelationship(target_role, 'CAN_BE_ASSUMED_BY', {
                    via: 'sts:AssumeRole'
                }, escalation_outcome)
                YIELD rel AS assume_rel

                UNWIND nodes(path_principal) + nodes(path_attach) + nodes(path_assume) + nodes(path_target) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_attach, path_assume, path_target,
                       escalation_outcome, modify_rel, assume_rel,
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

                // Create visualization
                CALL apoc.create.vNode(['EC2Instance'], {
                    id: 'potential-ec2-' + principal.arn,
                    name: 'New EC2 Instance',
                    description: 'Attacker-controlled EC2 with privileged role'
                })
                YIELD node AS ec2_node

                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'privesc-ec2-' + principal.arn + '-' + target_role.name,
                    name: CASE WHEN role_stmt IS NOT NULL THEN 'Effective Administrator' ELSE 'Elevated Access' END,
                    technique: 'iam:PassRole + ec2:RunInstances',
                    severity: CASE WHEN role_stmt IS NOT NULL THEN 'CRITICAL' ELSE 'HIGH' END,
                    reference: 'https://pathfinding.cloud/paths/ec2-001'
                })
                YIELD node AS escalation_outcome

                CALL apoc.create.vRelationship(principal, 'CAN_LAUNCH', {
                    via: 'ec2:RunInstances + iam:PassRole'
                }, ec2_node)
                YIELD rel AS launch_rel

                CALL apoc.create.vRelationship(ec2_node, 'ASSUMES_ROLE', {}, target_role)
                YIELD rel AS assumes_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {}, escalation_outcome)
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

                // Find roles that can be passed (ideally those trusting Lambda service)
                MATCH path_target = (aws)--(target_role:AWSRole)
                WHERE target_role.arn CONTAINS $provider_uid
                    AND any(resource IN stmt_passrole.resource WHERE
                        resource = '*'
                        OR target_role.arn CONTAINS resource
                        OR resource CONTAINS target_role.name
                    )

                // Check if target role has elevated permissions
                OPTIONAL MATCH (target_role)--(role_policy:AWSPolicy)--(role_stmt:AWSPolicyStatement)
                WHERE role_stmt.effect = 'Allow'
                    AND (
                        any(action IN role_stmt.action WHERE action = '*')
                        OR any(action IN role_stmt.action WHERE toLower(action) = 'iam:*')
                    )

                // Create visualization
                CALL apoc.create.vNode(['LambdaFunction'], {
                    id: 'potential-lambda-' + principal.arn,
                    name: 'New Lambda Function',
                    description: 'Attacker-controlled Lambda with privileged role'
                })
                YIELD node AS lambda_node

                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'privesc-lambda-' + principal.arn + '-' + target_role.name,
                    name: CASE WHEN role_stmt IS NOT NULL THEN 'Effective Administrator' ELSE 'Elevated Access' END,
                    technique: 'iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction',
                    severity: CASE WHEN role_stmt IS NOT NULL THEN 'CRITICAL' ELSE 'HIGH' END,
                    reference: 'https://pathfinding.cloud/paths/lambda-001'
                })
                YIELD node AS escalation_outcome

                CALL apoc.create.vRelationship(principal, 'CAN_CREATE_AND_INVOKE', {
                    via: 'lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole'
                }, lambda_node)
                YIELD rel AS create_rel

                CALL apoc.create.vRelationship(lambda_node, 'EXECUTES_AS', {}, target_role)
                YIELD rel AS executes_rel

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ACCESS', {}, escalation_outcome)
                YIELD rel AS grants_rel

                UNWIND nodes(path_principal) + nodes(path_passrole) + nodes(path_create) + nodes(path_invoke) + nodes(path_target) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_passrole, path_create, path_invoke, path_target,
                       lambda_node, escalation_outcome, create_rel, executes_rel, grants_rel,
                       collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
            """,
            parameters=[],
        ),
        AttackPathsQueryDefinition(
            id="aws-iam-privesc-role-chain",
            name="Privilege Escalation: Role Assumption Chains to Admin",
            description="Detect multi-hop role assumption chains where a principal can reach an administrative role through one or more intermediate role assumptions. This traces STS_ASSUMEROLE_ALLOW relationships to find paths to privileged roles.",
            provider="aws",
            cypher="""
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

                // Calculate chain length for visualization
                WITH principal, target_role, path_principal, path_chain, path_admin,
                     length(path_chain) as chain_length,
                     [node in nodes(path_chain) | node.name] as chain_nodes

                // Create escalation outcome visualization
                CALL apoc.create.vNode(['PrivilegeEscalation'], {
                    id: 'privesc-chain-' + principal.arn + '-' + target_role.name,
                    name: 'Effective Administrator',
                    technique: 'sts:AssumeRole chain (' + toString(chain_length) + ' hops)',
                    severity: CASE WHEN chain_length = 1 THEN 'CRITICAL' ELSE 'HIGH' END,
                    chain_length: chain_length,
                    chain_path: chain_nodes,
                    reference: 'https://pathfinding.cloud/paths/sts-001'
                })
                YIELD node AS escalation_outcome

                CALL apoc.create.vRelationship(target_role, 'GRANTS_ADMIN', {
                    hops: chain_length
                }, escalation_outcome)
                YIELD rel AS admin_rel

                UNWIND nodes(path_principal) + nodes(path_chain) + nodes(path_admin) as n
                OPTIONAL MATCH (n)-[pfr]-(pf:ProwlerFinding)
                WHERE pf.status = 'FAIL'

                RETURN path_principal, path_chain, path_admin,
                       escalation_outcome, admin_rel,
                       chain_length, chain_nodes,
                       collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
                ORDER BY chain_length ASC
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
