from api.attack_paths.queries.types import (
    AttackPathsQueryAttribution,
    AttackPathsQueryDefinition,
    AttackPathsQueryParameterDefinition,
)
from tasks.jobs.attack_paths.config import PROWLER_FINDING_LABEL


# Custom Attack Path Queries
# --------------------------

AWS_INTERNET_EXPOSED_EC2_SENSITIVE_S3_ACCESS = AttackPathsQueryDefinition(
    id="aws-internet-exposed-ec2-sensitive-s3-access",
    name="Internet-Exposed EC2 with Sensitive S3 Access",
    short_description="Find SSH-exposed EC2 instances that can assume roles to read tagged sensitive S3 buckets.",
    description="Detect EC2 instances with SSH exposed to the internet that can assume higher-privileged roles to read tagged sensitive S3 buckets despite bucket-level public access blocks.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        MATCH path_s3 = (aws:AWSAccount {{id: $provider_uid}})--(s3:S3Bucket)--(t:AWSTag)
        WHERE toLower(t.key) = toLower($tag_key) AND toLower(t.value) = toLower($tag_value)

        MATCH path_ec2 = (aws)--(ec2:EC2Instance)--(sg:EC2SecurityGroup)--(ipi:IpPermissionInbound)
        WHERE ec2.exposed_internet = true
            AND ipi.toport = 22

        MATCH path_role = (r:AWSRole)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE ANY(x IN stmt.resource WHERE x CONTAINS s3.name)
            AND ANY(x IN stmt.action WHERE toLower(x) =~ 's3:(listbucket|getobject).*')

        MATCH path_assume_role = (ec2)-[p:STS_ASSUMEROLE_ALLOW*1..9]-(r:AWSRole)

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, ec2)
        YIELD rel AS can_access

        UNWIND nodes(path_s3) + nodes(path_ec2) + nodes(path_role) + nodes(path_assume_role) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

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
)


# Basic Resource Queries
# ----------------------

AWS_RDS_INSTANCES = AttackPathsQueryDefinition(
    id="aws-rds-instances",
    name="RDS Instances Inventory",
    short_description="List all provisioned RDS database instances in the account.",
    description="List the selected AWS account alongside the RDS instances it owns.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(rds:RDSInstance)

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

AWS_RDS_UNENCRYPTED_STORAGE = AttackPathsQueryDefinition(
    id="aws-rds-unencrypted-storage",
    name="Unencrypted RDS Instances",
    short_description="Find RDS instances with storage encryption disabled.",
    description="Find RDS instances with storage encryption disabled within the selected account.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(rds:RDSInstance)
        WHERE rds.storage_encrypted = false

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

AWS_S3_ANONYMOUS_ACCESS_BUCKETS = AttackPathsQueryDefinition(
    id="aws-s3-anonymous-access-buckets",
    name="S3 Buckets with Anonymous Access",
    short_description="Find S3 buckets that allow anonymous access.",
    description="Find S3 buckets that allow anonymous access within the selected account.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(s3:S3Bucket)
        WHERE s3.anonymous_access = true

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

AWS_IAM_STATEMENTS_ALLOW_ALL_ACTIONS = AttackPathsQueryDefinition(
    id="aws-iam-statements-allow-all-actions",
    name="IAM Statements Allowing All Actions",
    short_description="Find IAM policy statements that allow all actions via wildcard (*).",
    description="Find IAM policy statements that allow all actions via '*' within the selected account.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(x IN stmt.action WHERE x = '*')

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

AWS_IAM_STATEMENTS_ALLOW_DELETE_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-statements-allow-delete-policy",
    name="IAM Statements Allowing Policy Deletion",
    short_description="Find IAM policy statements that allow iam:DeletePolicy.",
    description="Find IAM policy statements that allow the iam:DeletePolicy action within the selected account.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(x IN stmt.action WHERE x = "iam:DeletePolicy")

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

AWS_IAM_STATEMENTS_ALLOW_CREATE_ACTIONS = AttackPathsQueryDefinition(
    id="aws-iam-statements-allow-create-actions",
    name="IAM Statements Allowing Create Actions",
    short_description="Find IAM policy statements that allow any create action.",
    description="Find IAM policy statements that allow actions containing 'create' within the selected account.",
    provider="aws",
    cypher=f"""
        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(pol:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = "Allow"
            AND any(x IN stmt.action WHERE toLower(x) CONTAINS "create")

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)


# Network Exposure Queries
# ------------------------

AWS_EC2_INSTANCES_INTERNET_EXPOSED = AttackPathsQueryDefinition(
    id="aws-ec2-instances-internet-exposed",
    name="Internet-Exposed EC2 Instances",
    short_description="Find EC2 instances flagged as exposed to the internet.",
    description="Find EC2 instances flagged as exposed to the internet within the selected account.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(ec2:EC2Instance)
        WHERE ec2.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, ec2)
        YIELD rel AS can_access

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
    """,
    parameters=[],
)

AWS_SECURITY_GROUPS_OPEN_INTERNET_FACING = AttackPathsQueryDefinition(
    id="aws-security-groups-open-internet-facing",
    name="Open Security Groups on Internet-Facing Resources",
    short_description="Find internet-facing resources with security groups allowing inbound from 0.0.0.0/0.",
    description="Find internet-facing resources associated with security groups that allow inbound access from '0.0.0.0/0'.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        // Match EC2 instances that are internet-exposed with open security groups (0.0.0.0/0)
        MATCH path_ec2 = (aws:AWSAccount {{id: $provider_uid}})--(ec2:EC2Instance)--(sg:EC2SecurityGroup)--(ipi:IpPermissionInbound)--(ir:IpRange)
        WHERE ec2.exposed_internet = true
            AND ir.range = "0.0.0.0/0"

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, ec2)
        YIELD rel AS can_access

        UNWIND nodes(path_ec2) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_ec2, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
    """,
    parameters=[],
)

AWS_CLASSIC_ELB_INTERNET_EXPOSED = AttackPathsQueryDefinition(
    id="aws-classic-elb-internet-exposed",
    name="Internet-Exposed Classic Load Balancers",
    short_description="Find Classic Load Balancers exposed to the internet with their listeners.",
    description="Find Classic Load Balancers exposed to the internet along with their listeners.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(elb:LoadBalancer)--(listener:ELBListener)
        WHERE elb.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, elb)
        YIELD rel AS can_access

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
    """,
    parameters=[],
)

AWS_ELBV2_INTERNET_EXPOSED = AttackPathsQueryDefinition(
    id="aws-elbv2-internet-exposed",
    name="Internet-Exposed ALB/NLB Load Balancers",
    short_description="Find ELBv2 (ALB/NLB) load balancers exposed to the internet with their listeners.",
    description="Find ELBv2 load balancers exposed to the internet along with their listeners.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(elbv2:LoadBalancerV2)--(listener:ELBV2Listener)
        WHERE elbv2.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, elbv2)
        YIELD rel AS can_access

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path, collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr, internet, can_access
    """,
    parameters=[],
)

AWS_PUBLIC_IP_RESOURCE_LOOKUP = AttackPathsQueryDefinition(
    id="aws-public-ip-resource-lookup",
    name="Resource Lookup by Public IP",
    short_description="Find the AWS resource associated with a given public IP address.",
    description="Given a public IP address, find the related AWS resource and its adjacent node within the selected account.",
    provider="aws",
    cypher=f"""
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet'}})
        YIELD node AS internet

        CALL () {{
            MATCH path = (aws:AWSAccount {{id: $provider_uid}})-[r]-(x:EC2PrivateIp)-[q]-(y)
            WHERE x.public_ip = $ip
            RETURN path, x

            UNION MATCH path = (aws:AWSAccount {{id: $provider_uid}})-[r]-(x:EC2Instance)-[q]-(y)
            WHERE x.publicipaddress = $ip
            RETURN path, x

            UNION MATCH path = (aws:AWSAccount {{id: $provider_uid}})-[r]-(x:NetworkInterface)-[q]-(y)
            WHERE x.public_ip = $ip
            RETURN path, x

            UNION MATCH path = (aws:AWSAccount {{id: $provider_uid}})-[r]-(x:ElasticIPAddress)-[q]-(y)
            WHERE x.public_ip = $ip
            RETURN path, x
        }}

        WITH path, x, internet

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{}}, x)
        YIELD rel AS can_access

        UNWIND nodes(path) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

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
)

# Privilege Escalation Queries (based on pathfinding.cloud research)
# https://github.com/DataDog/pathfinding.cloud
# -------------------------------------------------------------------

# BEDROCK-001
AWS_BEDROCK_PRIVESC_PASSROLE_CODE_INTERPRETER = AttackPathsQueryDefinition(
    id="aws-bedrock-privesc-passrole-code-interpreter",
    name="Bedrock Code Interpreter with Privileged Role (BEDROCK-001)",
    short_description="Create a Bedrock AgentCore Code Interpreter with a privileged role attached.",
    description="Detect principals who can pass IAM roles and create Bedrock AgentCore Code Interpreters. This allows creating a code interpreter with a privileged role attached, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - BEDROCK-001 - iam:PassRole + bedrock-agentcore:CreateCodeInterpreter",
        link="https://pathfinding.cloud/paths/bedrock-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find bedrock-agentcore:CreateCodeInterpreter permission
        MATCH (principal)--(bedrock_policy:AWSPolicy)--(stmt_bedrock:AWSPolicyStatement)
        WHERE stmt_bedrock.effect = 'Allow'
            AND any(action IN stmt_bedrock.action WHERE
                toLower(action) = 'bedrock-agentcore:createcodeinterpreter'
                OR toLower(action) = 'bedrock-agentcore:*'
                OR action = '*'
            )

        // Find roles that trust Bedrock service (can be passed to Bedrock)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'bedrock.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# EC2-001
AWS_EC2_PRIVESC_PASSROLE_IAM = AttackPathsQueryDefinition(
    id="aws-ec2-privesc-passrole-iam",
    name="EC2 Instance Launch with Privileged Role (EC2-001)",
    short_description="Launch EC2 instances with privileged IAM roles to gain their permissions via IMDS.",
    description="Detect principals who can launch EC2 instances with privileged IAM roles attached. This allows gaining the permissions of the passed role by accessing the EC2 instance metadata service.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - EC2-001 - iam:PassRole + ec2:RunInstances",
        link="https://pathfinding.cloud/paths/ec2-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ec2:RunInstances permission
        MATCH (principal)--(ec2_policy:AWSPolicy)--(stmt_ec2:AWSPolicyStatement)
        WHERE stmt_ec2.effect = 'Allow'
            AND any(action IN stmt_ec2.action WHERE
                toLower(action) = 'ec2:runinstances'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find roles that trust EC2 service (can be passed to EC2)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ec2.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# EC2-002
AWS_EC2_PRIVESC_MODIFY_INSTANCE_ATTRIBUTE = AttackPathsQueryDefinition(
    id="aws-ec2-privesc-modify-instance-attribute",
    name="EC2 Role Hijacking via UserData Injection (EC2-002)",
    short_description="Inject malicious scripts into EC2 instance userData to gain the attached role's permissions.",
    description="Detect principals who can modify EC2 instance userData, stop, and start instances. This allows injecting malicious scripts that execute on instance restart, gaining the permissions of the instance's attached IAM role.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - EC2-002 - ec2:ModifyInstanceAttribute + ec2:StopInstances + ec2:StartInstances",
        link="https://pathfinding.cloud/paths/ec2-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ec2:ModifyInstanceAttribute permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(modify_policy:AWSPolicy)--(stmt_modify:AWSPolicyStatement)
        WHERE stmt_modify.effect = 'Allow'
            AND any(action IN stmt_modify.action WHERE
                toLower(action) = 'ec2:modifyinstanceattribute'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find ec2:StopInstances permission (can be same or different policy)
        MATCH (principal)--(stop_policy:AWSPolicy)--(stmt_stop:AWSPolicyStatement)
        WHERE stmt_stop.effect = 'Allow'
            AND any(action IN stmt_stop.action WHERE
                toLower(action) = 'ec2:stopinstances'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find ec2:StartInstances permission (can be same or different policy)
        MATCH (principal)--(start_policy:AWSPolicy)--(stmt_start:AWSPolicyStatement)
        WHERE stmt_start.effect = 'Allow'
            AND any(action IN stmt_start.action WHERE
                toLower(action) = 'ec2:startinstances'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find EC2 instances with instance profiles (potential targets)
        MATCH path_target = (aws)--(ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# EC2-003
AWS_EC2_PRIVESC_PASSROLE_SPOT_INSTANCES = AttackPathsQueryDefinition(
    id="aws-ec2-privesc-passrole-spot-instances",
    name="Spot Instance Launch with Privileged Role (EC2-003)",
    short_description="Launch EC2 Spot Instances with privileged IAM roles to gain their permissions via IMDS.",
    description="Detect principals who can pass IAM roles and request EC2 Spot Instances. This allows launching a spot instance with a privileged role attached, gaining that role's permissions via the instance metadata service.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - EC2-003 - iam:PassRole + ec2:RequestSpotInstances",
        link="https://pathfinding.cloud/paths/ec2-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ec2:RequestSpotInstances permission
        MATCH (principal)--(spot_policy:AWSPolicy)--(stmt_spot:AWSPolicyStatement)
        WHERE stmt_spot.effect = 'Allow'
            AND any(action IN stmt_spot.action WHERE
                toLower(action) = 'ec2:requestspotinstances'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find roles that trust EC2 service (can be passed to EC2 spot instances)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ec2.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# EC2-004
AWS_EC2_PRIVESC_LAUNCH_TEMPLATE = AttackPathsQueryDefinition(
    id="aws-ec2-privesc-launch-template",
    name="Launch Template Poisoning for Role Access (EC2-004)",
    short_description="Inject malicious userData into launch templates that reference privileged roles, no PassRole needed.",
    description="Detect principals who can create new launch template versions and modify launch templates. This allows injecting malicious user data into existing templates that already reference privileged IAM roles, without requiring iam:PassRole permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - EC2-004 - ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate",
        link="https://pathfinding.cloud/paths/ec2-004",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ec2:CreateLaunchTemplateVersion permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'ec2:createlaunchtemplateversion'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find ec2:ModifyLaunchTemplate permission
        MATCH (principal)--(modify_policy:AWSPolicy)--(stmt_modify:AWSPolicyStatement)
        WHERE stmt_modify.effect = 'Allow'
            AND any(action IN stmt_modify.action WHERE
                toLower(action) = 'ec2:modifylaunchtemplate'
                OR toLower(action) = 'ec2:*'
                OR action = '*'
            )

        // Find launch templates in the account (potential targets)
        MATCH path_target = (aws)--(template:LaunchTemplate)

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# ECS-001
AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-passrole-create-service",
    name="ECS Service Creation with Privileged Role (ECS-001 - New Cluster)",
    short_description="Create an ECS cluster and service with a privileged Fargate task role to execute arbitrary code.",
    description="Detect principals who can pass IAM roles, create ECS clusters, register task definitions, and create services. This allows creating a Fargate task with a privileged role attached, gaining that role's permissions to execute arbitrary code via the container.",
    provider="aws",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-001 - iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:CreateService",
        link="https://pathfinding.cloud/paths/ecs-001",
    ),
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ecs:CreateCluster permission
        MATCH (principal)--(cluster_policy:AWSPolicy)--(stmt_cluster:AWSPolicyStatement)
        WHERE stmt_cluster.effect = 'Allow'
            AND any(action IN stmt_cluster.action WHERE
                toLower(action) = 'ecs:createcluster'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:RegisterTaskDefinition permission
        MATCH (principal)--(taskdef_policy:AWSPolicy)--(stmt_taskdef:AWSPolicyStatement)
        WHERE stmt_taskdef.effect = 'Allow'
            AND any(action IN stmt_taskdef.action WHERE
                toLower(action) = 'ecs:registertaskdefinition'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:CreateService permission
        MATCH (principal)--(service_policy:AWSPolicy)--(stmt_service:AWSPolicyStatement)
        WHERE stmt_service.effect = 'Allow'
            AND any(action IN stmt_service.action WHERE
                toLower(action) = 'ecs:createservice'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find roles that trust ECS tasks service (can be passed to ECS tasks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ecs-tasks.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# ECS-002
AWS_ECS_PRIVESC_PASSROLE_RUN_TASK = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-passrole-run-task",
    name="ECS Task Execution with Privileged Role (ECS-002 - New Cluster)",
    short_description="Create an ECS cluster and run a one-off Fargate task with a privileged role to execute arbitrary code.",
    description="Detect principals who can pass IAM roles, create ECS clusters, register task definitions, and run tasks. This allows creating a Fargate task with a privileged role attached, gaining that role's permissions to execute arbitrary code via the container. Unlike ecs:CreateService, ecs:RunTask executes the task once without creating a persistent service.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-002 - iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:RunTask",
        link="https://pathfinding.cloud/paths/ecs-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ecs:CreateCluster permission
        MATCH (principal)--(cluster_policy:AWSPolicy)--(stmt_cluster:AWSPolicyStatement)
        WHERE stmt_cluster.effect = 'Allow'
            AND any(action IN stmt_cluster.action WHERE
                toLower(action) = 'ecs:createcluster'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:RegisterTaskDefinition permission
        MATCH (principal)--(taskdef_policy:AWSPolicy)--(stmt_taskdef:AWSPolicyStatement)
        WHERE stmt_taskdef.effect = 'Allow'
            AND any(action IN stmt_taskdef.action WHERE
                toLower(action) = 'ecs:registertaskdefinition'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:RunTask permission
        MATCH (principal)--(runtask_policy:AWSPolicy)--(stmt_runtask:AWSPolicyStatement)
        WHERE stmt_runtask.effect = 'Allow'
            AND any(action IN stmt_runtask.action WHERE
                toLower(action) = 'ecs:runtask'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find roles that trust ECS tasks service (can be passed to ECS tasks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ecs-tasks.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# ECS-003
AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE_EXISTING_CLUSTER = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-passrole-create-service-existing-cluster",
    name="ECS Service Creation with Privileged Role (ECS-003 - Existing Cluster)",
    short_description="Deploy a Fargate service with a privileged role on an existing ECS cluster.",
    description="Detect principals who can pass IAM roles, register ECS task definitions, and create services on existing clusters. Unlike ECS-001, this does not require ecs:CreateCluster since it targets clusters that already exist. The attacker registers a task definition with a privileged role and launches it as a Fargate service, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-003 - iam:PassRole + ecs:RegisterTaskDefinition + ecs:CreateService",
        link="https://pathfinding.cloud/paths/ecs-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ecs:RegisterTaskDefinition permission
        MATCH (principal)--(taskdef_policy:AWSPolicy)--(stmt_taskdef:AWSPolicyStatement)
        WHERE stmt_taskdef.effect = 'Allow'
            AND any(action IN stmt_taskdef.action WHERE
                toLower(action) = 'ecs:registertaskdefinition'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:CreateService permission
        MATCH (principal)--(service_policy:AWSPolicy)--(stmt_service:AWSPolicyStatement)
        WHERE stmt_service.effect = 'Allow'
            AND any(action IN stmt_service.action WHERE
                toLower(action) = 'ecs:createservice'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find roles that trust ECS tasks service (can be passed to ECS tasks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ecs-tasks.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# ECS-004
AWS_ECS_PRIVESC_PASSROLE_RUN_TASK_EXISTING_CLUSTER = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-passrole-run-task-existing-cluster",
    name="ECS Task Execution with Privileged Role (ECS-004 - Existing Cluster)",
    short_description="Run a one-off Fargate task with a privileged role on an existing ECS cluster.",
    description="Detect principals who can pass IAM roles, register ECS task definitions, and run tasks on existing clusters. Unlike ECS-002, this does not require ecs:CreateCluster since it targets clusters that already exist. The attacker registers a task definition with a privileged role and runs it as a one-off Fargate task, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-004 - iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask",
        link="https://pathfinding.cloud/paths/ecs-004",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find ecs:RegisterTaskDefinition permission
        MATCH (principal)--(taskdef_policy:AWSPolicy)--(stmt_taskdef:AWSPolicyStatement)
        WHERE stmt_taskdef.effect = 'Allow'
            AND any(action IN stmt_taskdef.action WHERE
                toLower(action) = 'ecs:registertaskdefinition'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:RunTask permission
        MATCH (principal)--(runtask_policy:AWSPolicy)--(stmt_runtask:AWSPolicyStatement)
        WHERE stmt_runtask.effect = 'Allow'
            AND any(action IN stmt_runtask.action WHERE
                toLower(action) = 'ecs:runtask'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find roles that trust ECS tasks service (can be passed to ECS tasks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ecs-tasks.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# GLUE-001
AWS_GLUE_PRIVESC_PASSROLE_DEV_ENDPOINT = AttackPathsQueryDefinition(
    id="aws-glue-privesc-passrole-dev-endpoint",
    name="Glue Dev Endpoint with Privileged Role (GLUE-001)",
    short_description="Create a Glue development endpoint with a privileged role attached to gain its permissions.",
    description="Detect principals who can pass IAM roles and create Glue development endpoints. This allows creating a dev endpoint with a privileged role attached, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-001 - iam:PassRole + glue:CreateDevEndpoint",
        link="https://pathfinding.cloud/paths/glue-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PassRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(passrole_policy:AWSPolicy)--(stmt_passrole:AWSPolicyStatement)
        WHERE stmt_passrole.effect = 'Allow'
            AND any(action IN stmt_passrole.action WHERE
                toLower(action) = 'iam:passrole'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find glue:CreateDevEndpoint permission
        MATCH (principal)--(glue_policy:AWSPolicy)--(stmt_glue:AWSPolicyStatement)
        WHERE stmt_glue.effect = 'Allow'
            AND any(action IN stmt_glue.action WHERE
                toLower(action) = 'glue:createdevendpoint'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (can be passed to Glue)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'glue.amazonaws.com'}})
        WHERE any(resource IN stmt_passrole.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-014
AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-role-policy-assume-role",
    name="Role Policy Attachment and Assumption (IAM-014)",
    short_description="Attach policies to IAM roles and then assume them to gain elevated access.",
    description="Detect principals who can both attach policies to roles AND assume those roles. This allows modifying a role's permissions then assuming it to gain elevated access.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-014 - iam:AttachRolePolicy + sts:AssumeRole",
        link="https://pathfinding.cloud/paths/iam-014",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:AttachRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(attach_policy:AWSPolicy)--(stmt_attach:AWSPolicyStatement)
        WHERE stmt_attach.effect = 'Allow'
            AND any(action IN stmt_attach.action WHERE
                toLower(action) = 'iam:attachrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find sts:AssumeRole permission
        MATCH (principal)--(assume_policy:AWSPolicy)--(stmt_assume:AWSPolicyStatement)
        WHERE stmt_assume.effect = 'Allow'
            AND any(action IN stmt_assume.action WHERE
                toLower(action) = 'sts:assumerole'
                OR toLower(action) = 'sts:*'
                OR action = '*'
            )

        // Find target roles that the principal can both modify AND assume
        MATCH path_target = (aws)--(target_role:AWSRole)
        WHERE target_role.arn CONTAINS $provider_uid
            AND any(resource IN stmt_attach.resource WHERE
                resource = '*'
                OR target_role.arn CONTAINS resource
                OR resource CONTAINS target_role.name
            )
            AND any(resource IN stmt_assume.resource WHERE
                resource = '*'
                OR target_role.arn CONTAINS resource
                OR resource CONTAINS target_role.name
            )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# AWS Queries List
# ----------------

AWS_QUERIES: list[AttackPathsQueryDefinition] = [
    AWS_INTERNET_EXPOSED_EC2_SENSITIVE_S3_ACCESS,
    AWS_RDS_INSTANCES,
    AWS_RDS_UNENCRYPTED_STORAGE,
    AWS_S3_ANONYMOUS_ACCESS_BUCKETS,
    AWS_IAM_STATEMENTS_ALLOW_ALL_ACTIONS,
    AWS_IAM_STATEMENTS_ALLOW_DELETE_POLICY,
    AWS_IAM_STATEMENTS_ALLOW_CREATE_ACTIONS,
    AWS_EC2_INSTANCES_INTERNET_EXPOSED,
    AWS_SECURITY_GROUPS_OPEN_INTERNET_FACING,
    AWS_CLASSIC_ELB_INTERNET_EXPOSED,
    AWS_ELBV2_INTERNET_EXPOSED,
    AWS_PUBLIC_IP_RESOURCE_LOOKUP,
    AWS_BEDROCK_PRIVESC_PASSROLE_CODE_INTERPRETER,
    AWS_EC2_PRIVESC_PASSROLE_IAM,
    AWS_EC2_PRIVESC_MODIFY_INSTANCE_ATTRIBUTE,
    AWS_EC2_PRIVESC_PASSROLE_SPOT_INSTANCES,
    AWS_EC2_PRIVESC_LAUNCH_TEMPLATE,
    AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE,
    AWS_ECS_PRIVESC_PASSROLE_RUN_TASK,
    AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE_EXISTING_CLUSTER,
    AWS_ECS_PRIVESC_PASSROLE_RUN_TASK_EXISTING_CLUSTER,
    AWS_GLUE_PRIVESC_PASSROLE_DEV_ENDPOINT,
    AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_ASSUME_ROLE,
]
