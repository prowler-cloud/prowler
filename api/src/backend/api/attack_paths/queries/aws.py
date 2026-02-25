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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
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

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, ec2)
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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(ec2:EC2Instance)
        WHERE ec2.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, ec2)
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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
        YIELD node AS internet

        // Match EC2 instances that are internet-exposed with open security groups (0.0.0.0/0)
        MATCH path_ec2 = (aws:AWSAccount {{id: $provider_uid}})--(ec2:EC2Instance)--(sg:EC2SecurityGroup)--(ipi:IpPermissionInbound)--(ir:IpRange)
        WHERE ec2.exposed_internet = true
            AND ir.range = "0.0.0.0/0"

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, ec2)
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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(elb:LoadBalancer)--(listener:ELBListener)
        WHERE elb.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, elb)
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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
        YIELD node AS internet

        MATCH path = (aws:AWSAccount {{id: $provider_uid}})--(elbv2:LoadBalancerV2)--(listener:ELBV2Listener)
        WHERE elbv2.exposed_internet = true

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, elbv2)
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
        CALL apoc.create.vNode(['Internet'], {{id: 'Internet', name: 'Internet', provider_id: $provider_id}})
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

        CALL apoc.create.vRelationship(internet, 'CAN_ACCESS', {{provider_id: $provider_id}}, x)
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

# APPRUNNER-001
AWS_APPRUNNER_PRIVESC_PASSROLE_CREATE_SERVICE = AttackPathsQueryDefinition(
    id="aws-apprunner-privesc-passrole-create-service",
    name="App Runner Service Creation with Privileged Role (APPRUNNER-001)",
    short_description="Create an App Runner service with a privileged IAM role to gain its permissions.",
    description="Detect principals who can pass IAM roles and create App Runner services. This allows creating a service with a privileged role attached, gaining that role's permissions via StartCommand execution, a container web shell, or a malicious apprunner.yaml configuration.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - APPRUNNER-001 - iam:PassRole + apprunner:CreateService",
        link="https://pathfinding.cloud/paths/apprunner-001",
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

        // Find apprunner:CreateService permission
        MATCH (principal)--(apprunner_policy:AWSPolicy)--(stmt_apprunner:AWSPolicyStatement)
        WHERE stmt_apprunner.effect = 'Allow'
            AND any(action IN stmt_apprunner.action WHERE
                toLower(action) = 'apprunner:createservice'
                OR toLower(action) = 'apprunner:*'
                OR action = '*'
            )

        // Find roles that trust App Runner tasks service (can be passed to App Runner)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'tasks.apprunner.amazonaws.com'}})
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

# APPRUNNER-002
AWS_APPRUNNER_PRIVESC_UPDATE_SERVICE = AttackPathsQueryDefinition(
    id="aws-apprunner-privesc-update-service",
    name="App Runner Service Update for Role Access (APPRUNNER-002)",
    short_description="Update an existing App Runner service to leverage its already-attached privileged role.",
    description="Detect principals who can update existing App Runner services. This allows modifying a service's configuration to execute arbitrary code with the service's already-attached IAM role, without requiring iam:PassRole. Exploitation methods include injecting a malicious StartCommand, updating to a container image with a web shell, or pointing to a repository with a malicious apprunner.yaml file.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - APPRUNNER-002 - apprunner:UpdateService",
        link="https://pathfinding.cloud/paths/apprunner-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with apprunner:UpdateService permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(update_policy:AWSPolicy)--(stmt_update:AWSPolicyStatement)
        WHERE stmt_update.effect = 'Allow'
            AND any(action IN stmt_update.action WHERE
                toLower(action) = 'apprunner:updateservice'
                OR toLower(action) = 'apprunner:*'
                OR action = '*'
            )

        // Find existing App Runner services with roles attached (potential targets)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'tasks.apprunner.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# BEDROCK-001
AWS_BEDROCK_PRIVESC_PASSROLE_CODE_INTERPRETER = AttackPathsQueryDefinition(
    id="aws-bedrock-privesc-passrole-code-interpreter",
    name="Bedrock Code Interpreter with Privileged Role (BEDROCK-001)",
    short_description="Create a Bedrock AgentCore Code Interpreter with a privileged role attached.",
    description="Detect principals who can pass IAM roles and create Bedrock AgentCore Code Interpreters. This allows creating a code interpreter with a privileged role attached, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - BEDROCK-001 - iam:PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter",
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

        // Find bedrock-agentcore:StartCodeInterpreterSession permission
        MATCH (principal)--(session_policy:AWSPolicy)--(stmt_session:AWSPolicyStatement)
        WHERE stmt_session.effect = 'Allow'
            AND any(action IN stmt_session.action WHERE
                toLower(action) = 'bedrock-agentcore:startcodeinterpretersession'
                OR toLower(action) = 'bedrock-agentcore:*'
                OR action = '*'
            )

        // Find bedrock-agentcore:InvokeCodeInterpreter permission
        MATCH (principal)--(invoke_policy:AWSPolicy)--(stmt_invoke:AWSPolicyStatement)
        WHERE stmt_invoke.effect = 'Allow'
            AND any(action IN stmt_invoke.action WHERE
                toLower(action) = 'bedrock-agentcore:invokecodeinterpreter'
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

# BEDROCK-002
AWS_BEDROCK_PRIVESC_INVOKE_CODE_INTERPRETER = AttackPathsQueryDefinition(
    id="aws-bedrock-privesc-invoke-code-interpreter",
    name="Bedrock Code Interpreter Session Hijacking (BEDROCK-002)",
    short_description="Start a session on an existing Bedrock code interpreter to exfiltrate its privileged role credentials.",
    description="Detect principals who can start sessions and invoke code on existing Bedrock AgentCore code interpreters. This allows executing arbitrary Python code within an interpreter that has a privileged role attached, gaining that role's credentials via the MicroVM Metadata Service without requiring iam:PassRole.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - BEDROCK-002 - bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter",
        link="https://pathfinding.cloud/paths/bedrock-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with bedrock-agentcore:StartCodeInterpreterSession permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(session_policy:AWSPolicy)--(stmt_session:AWSPolicyStatement)
        WHERE stmt_session.effect = 'Allow'
            AND any(action IN stmt_session.action WHERE
                toLower(action) = 'bedrock-agentcore:startcodeinterpretersession'
                OR toLower(action) = 'bedrock-agentcore:*'
                OR action = '*'
            )

        // Find bedrock-agentcore:InvokeCodeInterpreter permission
        MATCH (principal)--(invoke_policy:AWSPolicy)--(stmt_invoke:AWSPolicyStatement)
        WHERE stmt_invoke.effect = 'Allow'
            AND any(action IN stmt_invoke.action WHERE
                toLower(action) = 'bedrock-agentcore:invokecodeinterpreter'
                OR toLower(action) = 'bedrock-agentcore:*'
                OR action = '*'
            )

        // Find roles that trust Bedrock service (already attached to existing code interpreters)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'bedrock.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# CLOUDFORMATION-001
AWS_CLOUDFORMATION_PRIVESC_PASSROLE_CREATE_STACK = AttackPathsQueryDefinition(
    id="aws-cloudformation-privesc-passrole-create-stack",
    name="CloudFormation Stack Creation with Privileged Role (CLOUDFORMATION-001)",
    short_description="Create a CloudFormation stack with a privileged role to provision arbitrary AWS resources.",
    description="Detect principals who can pass IAM roles and create CloudFormation stacks. This allows launching a stack with a malicious template that executes with the passed role's permissions, enabling creation of resources like IAM users, Lambda functions, or EC2 instances controlled by the attacker.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CLOUDFORMATION-001 - iam:PassRole + cloudformation:CreateStack",
        link="https://pathfinding.cloud/paths/cloudformation-001",
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

        // Find cloudformation:CreateStack permission
        MATCH (principal)--(cfn_policy:AWSPolicy)--(stmt_cfn:AWSPolicyStatement)
        WHERE stmt_cfn.effect = 'Allow'
            AND any(action IN stmt_cfn.action WHERE
                toLower(action) = 'cloudformation:createstack'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find roles that trust CloudFormation service (can be passed to CloudFormation)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'cloudformation.amazonaws.com'}})
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

# CLOUDFORMATION-002
AWS_CLOUDFORMATION_PRIVESC_UPDATE_STACK = AttackPathsQueryDefinition(
    id="aws-cloudformation-privesc-update-stack",
    name="CloudFormation Stack Update for Role Access (CLOUDFORMATION-002)",
    short_description="Update an existing CloudFormation stack to leverage its already-attached privileged service role.",
    description="Detect principals who can update existing CloudFormation stacks. This allows modifying a stack's template to add new resources (such as IAM roles with admin access) that are created with the stack's already-attached service role permissions, without requiring iam:PassRole.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CLOUDFORMATION-002 - cloudformation:UpdateStack",
        link="https://pathfinding.cloud/paths/cloudformation-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with cloudformation:UpdateStack permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(update_policy:AWSPolicy)--(stmt_update:AWSPolicyStatement)
        WHERE stmt_update.effect = 'Allow'
            AND any(action IN stmt_update.action WHERE
                toLower(action) = 'cloudformation:updatestack'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find roles that trust CloudFormation service (already attached to existing stacks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'cloudformation.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# CLOUDFORMATION-003
AWS_CLOUDFORMATION_PRIVESC_PASSROLE_CREATE_STACKSET = AttackPathsQueryDefinition(
    id="aws-cloudformation-privesc-passrole-create-stackset",
    name="CloudFormation StackSet Creation with Privileged Role (CLOUDFORMATION-003)",
    short_description="Create a CloudFormation StackSet with a privileged execution role to provision arbitrary resources across accounts.",
    description="Detect principals who can pass IAM roles, create CloudFormation StackSets, and deploy stack instances. This allows creating a StackSet with a malicious template and a privileged execution role, then deploying instances that create resources (such as IAM roles with admin access) using that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CLOUDFORMATION-003 - iam:PassRole + cloudformation:CreateStackSet + cloudformation:CreateStackInstances",
        link="https://pathfinding.cloud/paths/cloudformation-003",
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

        // Find cloudformation:CreateStackSet permission
        MATCH (principal)--(cfn_policy:AWSPolicy)--(stmt_cfn:AWSPolicyStatement)
        WHERE stmt_cfn.effect = 'Allow'
            AND any(action IN stmt_cfn.action WHERE
                toLower(action) = 'cloudformation:createstackset'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find cloudformation:CreateStackInstances permission
        MATCH (principal)--(cfn_instances_policy:AWSPolicy)--(stmt_cfn_instances:AWSPolicyStatement)
        WHERE stmt_cfn_instances.effect = 'Allow'
            AND any(action IN stmt_cfn_instances.action WHERE
                toLower(action) = 'cloudformation:createstackinstances'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find roles that trust CloudFormation service (can be passed as execution role)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'cloudformation.amazonaws.com'}})
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

# CLOUDFORMATION-004
AWS_CLOUDFORMATION_PRIVESC_PASSROLE_UPDATE_STACKSET = AttackPathsQueryDefinition(
    id="aws-cloudformation-privesc-passrole-update-stackset",
    name="CloudFormation StackSet Update with Privileged Role (CLOUDFORMATION-004)",
    short_description="Update an existing CloudFormation StackSet to inject malicious resources using a privileged execution role.",
    description="Detect principals who can pass IAM roles and update CloudFormation StackSets. This allows modifying an existing StackSet's template to add resources (such as IAM roles with admin access) that are provisioned by the StackSet's privileged execution role across target accounts.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CLOUDFORMATION-004 - iam:PassRole + cloudformation:UpdateStackSet",
        link="https://pathfinding.cloud/paths/cloudformation-004",
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

        // Find cloudformation:UpdateStackSet permission
        MATCH (principal)--(cfn_policy:AWSPolicy)--(stmt_cfn:AWSPolicyStatement)
        WHERE stmt_cfn.effect = 'Allow'
            AND any(action IN stmt_cfn.action WHERE
                toLower(action) = 'cloudformation:updatestackset'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find roles that trust CloudFormation service (can be passed as execution role)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'cloudformation.amazonaws.com'}})
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

# CLOUDFORMATION-005
AWS_CLOUDFORMATION_PRIVESC_CHANGESET = AttackPathsQueryDefinition(
    id="aws-cloudformation-privesc-changeset",
    name="CloudFormation Change Set Privilege Escalation (CLOUDFORMATION-005)",
    short_description="Create and execute a change set on an existing stack to leverage its privileged service role.",
    description="Detect principals who can create and execute CloudFormation change sets. This allows modifying an existing stack's template through a staged change set, inheriting the stack's already-attached service role permissions to provision arbitrary resources without requiring iam:PassRole.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CLOUDFORMATION-005 - cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet",
        link="https://pathfinding.cloud/paths/cloudformation-005",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with cloudformation:CreateChangeSet permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'cloudformation:createchangeset'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find cloudformation:ExecuteChangeSet permission
        MATCH (principal)--(exec_policy:AWSPolicy)--(stmt_exec:AWSPolicyStatement)
        WHERE stmt_exec.effect = 'Allow'
            AND any(action IN stmt_exec.action WHERE
                toLower(action) = 'cloudformation:executechangeset'
                OR toLower(action) = 'cloudformation:*'
                OR action = '*'
            )

        // Find roles that trust CloudFormation service (already attached to existing stacks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'cloudformation.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# CODEBUILD-001
AWS_CODEBUILD_PRIVESC_PASSROLE_CREATE_PROJECT = AttackPathsQueryDefinition(
    id="aws-codebuild-privesc-passrole-create-project",
    name="CodeBuild Project Creation with Privileged Role (CODEBUILD-001)",
    short_description="Create a CodeBuild project with a privileged role to execute arbitrary code via a malicious buildspec.",
    description="Detect principals who can pass IAM roles, create CodeBuild projects, and start builds. This allows creating a project with a privileged role attached and executing arbitrary code through a malicious buildspec, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CODEBUILD-001 - iam:PassRole + codebuild:CreateProject + codebuild:StartBuild",
        link="https://pathfinding.cloud/paths/codebuild-001",
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

        // Find codebuild:CreateProject permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'codebuild:createproject'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find codebuild:StartBuild permission
        MATCH (principal)--(build_policy:AWSPolicy)--(stmt_build:AWSPolicyStatement)
        WHERE stmt_build.effect = 'Allow'
            AND any(action IN stmt_build.action WHERE
                toLower(action) = 'codebuild:startbuild'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find roles that trust CodeBuild service (can be passed to CodeBuild)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'codebuild.amazonaws.com'}})
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

# CODEBUILD-002
AWS_CODEBUILD_PRIVESC_START_BUILD = AttackPathsQueryDefinition(
    id="aws-codebuild-privesc-start-build",
    name="CodeBuild Buildspec Override for Role Access (CODEBUILD-002)",
    short_description="Start a build on an existing CodeBuild project with a buildspec override to execute code with its privileged role.",
    description="Detect principals who can start builds on existing CodeBuild projects. This allows overriding the buildspec with malicious commands that execute with the project's already-attached service role permissions, without requiring iam:PassRole or codebuild:CreateProject.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CODEBUILD-002 - codebuild:StartBuild",
        link="https://pathfinding.cloud/paths/codebuild-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with codebuild:StartBuild permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(build_policy:AWSPolicy)--(stmt_build:AWSPolicyStatement)
        WHERE stmt_build.effect = 'Allow'
            AND any(action IN stmt_build.action WHERE
                toLower(action) = 'codebuild:startbuild'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find roles that trust CodeBuild service (already attached to existing projects)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'codebuild.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# CODEBUILD-003
AWS_CODEBUILD_PRIVESC_START_BUILD_BATCH = AttackPathsQueryDefinition(
    id="aws-codebuild-privesc-start-build-batch",
    name="CodeBuild Batch Buildspec Override for Role Access (CODEBUILD-003)",
    short_description="Start a batch build on an existing CodeBuild project with a buildspec override to execute code with its privileged role.",
    description="Detect principals who can start batch builds on existing CodeBuild projects. This allows overriding the buildspec with malicious commands that execute with the project's already-attached service role permissions, without requiring iam:PassRole or codebuild:CreateProject.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CODEBUILD-003 - codebuild:StartBuildBatch",
        link="https://pathfinding.cloud/paths/codebuild-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with codebuild:StartBuildBatch permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(build_policy:AWSPolicy)--(stmt_build:AWSPolicyStatement)
        WHERE stmt_build.effect = 'Allow'
            AND any(action IN stmt_build.action WHERE
                toLower(action) = 'codebuild:startbuildbatch'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find roles that trust CodeBuild service (already attached to existing projects)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'codebuild.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# CODEBUILD-004
AWS_CODEBUILD_PRIVESC_PASSROLE_CREATE_PROJECT_BATCH = AttackPathsQueryDefinition(
    id="aws-codebuild-privesc-passrole-create-project-batch",
    name="CodeBuild Batch Project Creation with Privileged Role (CODEBUILD-004)",
    short_description="Create a CodeBuild project configured for batch builds with a privileged role to execute arbitrary code via a malicious buildspec.",
    description="Detect principals who can pass IAM roles, create CodeBuild projects, and start batch builds. This allows creating a project with a privileged role attached and executing arbitrary code through a malicious batch buildspec, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - CODEBUILD-004 - iam:PassRole + codebuild:CreateProject + codebuild:StartBuildBatch",
        link="https://pathfinding.cloud/paths/codebuild-004",
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

        // Find codebuild:CreateProject permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'codebuild:createproject'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find codebuild:StartBuildBatch permission
        MATCH (principal)--(batch_policy:AWSPolicy)--(stmt_batch:AWSPolicyStatement)
        WHERE stmt_batch.effect = 'Allow'
            AND any(action IN stmt_batch.action WHERE
                toLower(action) = 'codebuild:startbuildbatch'
                OR toLower(action) = 'codebuild:*'
                OR action = '*'
            )

        // Find roles that trust CodeBuild service (can be passed to CodeBuild)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'codebuild.amazonaws.com'}})
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

# DATAPIPELINE-001
AWS_DATAPIPELINE_PRIVESC_PASSROLE_CREATE_PIPELINE = AttackPathsQueryDefinition(
    id="aws-datapipeline-privesc-passrole-create-pipeline",
    name="Data Pipeline Creation with Privileged Role (DATAPIPELINE-001)",
    short_description="Create a Data Pipeline with a privileged role to execute arbitrary commands on provisioned infrastructure.",
    description="Detect principals who can pass IAM roles, create Data Pipelines, define pipeline objects, and activate them. This allows creating a pipeline with a privileged role attached and executing arbitrary commands on the provisioned EC2 instances or EMR clusters, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - DATAPIPELINE-001 - iam:PassRole + datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + datapipeline:ActivatePipeline",
        link="https://pathfinding.cloud/paths/datapipeline-001",
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

        // Find datapipeline:CreatePipeline permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'datapipeline:createpipeline'
                OR toLower(action) = 'datapipeline:*'
                OR action = '*'
            )

        // Find datapipeline:PutPipelineDefinition permission
        MATCH (principal)--(put_policy:AWSPolicy)--(stmt_put:AWSPolicyStatement)
        WHERE stmt_put.effect = 'Allow'
            AND any(action IN stmt_put.action WHERE
                toLower(action) = 'datapipeline:putpipelinedefinition'
                OR toLower(action) = 'datapipeline:*'
                OR action = '*'
            )

        // Find datapipeline:ActivatePipeline permission
        MATCH (principal)--(activate_policy:AWSPolicy)--(stmt_activate:AWSPolicyStatement)
        WHERE stmt_activate.effect = 'Allow'
            AND any(action IN stmt_activate.action WHERE
                toLower(action) = 'datapipeline:activatepipeline'
                OR toLower(action) = 'datapipeline:*'
                OR action = '*'
            )

        // Find roles that trust Data Pipeline or EMR service (can be passed to DataPipeline)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(trusted_principal:AWSPrincipal)
        WHERE trusted_principal.arn IN ['datapipeline.amazonaws.com', 'elasticmapreduce.amazonaws.com']
            AND any(resource IN stmt_passrole.resource WHERE
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

# EC2INSTANCECONNECT-003
AWS_EC2INSTANCECONNECT_PRIVESC_SEND_SSH_PUBLIC_KEY = AttackPathsQueryDefinition(
    id="aws-ec2instanceconnect-privesc-send-ssh-public-key",
    name="EC2 Instance Connect SSH Access for Role Credentials (EC2INSTANCECONNECT-003)",
    short_description="Push a temporary SSH key to an EC2 instance via Instance Connect to access its attached role credentials through IMDS.",
    description="Detect principals who can send SSH public keys via EC2 Instance Connect. This allows establishing an SSH session on a running EC2 instance and retrieving the attached IAM role's temporary credentials from the Instance Metadata Service (IMDS), gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - EC2INSTANCECONNECT-003 - ec2-instance-connect:SendSSHPublicKey",
        link="https://pathfinding.cloud/paths/ec2instanceconnect-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ec2-instance-connect:SendSSHPublicKey permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(connect_policy:AWSPolicy)--(stmt_connect:AWSPolicyStatement)
        WHERE stmt_connect.effect = 'Allow'
            AND any(action IN stmt_connect.action WHERE
                toLower(action) = 'ec2-instance-connect:sendsshpublickey'
                OR toLower(action) = 'ec2-instance-connect:*'
                OR action = '*'
            )

        // Find EC2 instances with attached roles (targets for credential theft via IMDS)
        MATCH path_target = (aws)--(ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)

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

# ECS-005
AWS_ECS_PRIVESC_PASSROLE_START_TASK_EXISTING_CLUSTER = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-passrole-start-task-existing-cluster",
    name="ECS Task Start with Privileged Role on EC2 (ECS-005 - Existing Cluster)",
    short_description="Register a task definition with a privileged role and start it on an EC2 container instance to execute arbitrary code.",
    description="Detect principals who can pass IAM roles, register ECS task definitions, and start tasks on existing EC2 container instances. Unlike ecs:RunTask which works with both EC2 and Fargate, ecs:StartTask is specific to EC2 launch types and requires specifying an existing container instance ARN. The attacker registers a task definition with a privileged role and starts it on a container instance, gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-005 - iam:PassRole + ecs:RegisterTaskDefinition + ecs:StartTask",
        link="https://pathfinding.cloud/paths/ecs-005",
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

        // Find ecs:StartTask permission
        MATCH (principal)--(starttask_policy:AWSPolicy)--(stmt_starttask:AWSPolicyStatement)
        WHERE stmt_starttask.effect = 'Allow'
            AND any(action IN stmt_starttask.action WHERE
                toLower(action) = 'ecs:starttask'
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

# ECS-006
AWS_ECS_PRIVESC_EXECUTE_COMMAND = AttackPathsQueryDefinition(
    id="aws-ecs-privesc-execute-command",
    name="ECS Exec Container Hijacking for Role Credentials (ECS-006)",
    short_description="Shell into a running ECS container via ECS Exec to steal the attached task role's credentials.",
    description="Detect principals who can execute commands in running ECS containers and describe tasks. This allows establishing an interactive shell session in a container where ECS Exec is enabled, then retrieving the task role's temporary credentials from the container metadata service, without requiring iam:PassRole.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - ECS-006 - ecs:ExecuteCommand + ecs:DescribeTasks",
        link="https://pathfinding.cloud/paths/ecs-006",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ecs:ExecuteCommand permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(exec_policy:AWSPolicy)--(stmt_exec:AWSPolicyStatement)
        WHERE stmt_exec.effect = 'Allow'
            AND any(action IN stmt_exec.action WHERE
                toLower(action) = 'ecs:executecommand'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find ecs:DescribeTasks permission (required by AWS CLI to get container runtime ID)
        MATCH (principal)--(describe_policy:AWSPolicy)--(stmt_describe:AWSPolicyStatement)
        WHERE stmt_describe.effect = 'Allow'
            AND any(action IN stmt_describe.action WHERE
                toLower(action) = 'ecs:describetasks'
                OR toLower(action) = 'ecs:*'
                OR action = '*'
            )

        // Find roles that trust ECS tasks service (already attached to running tasks)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'ecs-tasks.amazonaws.com'}})

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

# GLUE-002
AWS_GLUE_PRIVESC_UPDATE_DEV_ENDPOINT = AttackPathsQueryDefinition(
    id="aws-glue-privesc-update-dev-endpoint",
    name="Glue Dev Endpoint SSH Hijacking via Update (GLUE-002)",
    short_description="Update an existing Glue development endpoint to inject an SSH public key and access its attached role credentials.",
    description="Detect principals who can update Glue development endpoints. This allows adding an attacker-controlled SSH public key to an existing dev endpoint that already has a privileged role attached, then SSHing into it to steal the role's temporary credentials without requiring iam:PassRole.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-002 - glue:UpdateDevEndpoint",
        link="https://pathfinding.cloud/paths/glue-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with glue:UpdateDevEndpoint permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'glue:updatedevendpoint'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (already attached to existing dev endpoints)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'glue.amazonaws.com'}})

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# GLUE-003
AWS_GLUE_PRIVESC_PASSROLE_CREATE_JOB = AttackPathsQueryDefinition(
    id="aws-glue-privesc-passrole-create-job",
    name="Glue Job Creation with Privileged Role (GLUE-003)",
    short_description="Create a Glue job with a privileged role and start it to execute arbitrary code with that role's permissions.",
    description="Detect principals who can pass IAM roles, create Glue jobs, and start job runs. This allows creating a Python shell job with a privileged role attached and executing arbitrary code that modifies IAM permissions, a cost-effective alternative to Glue development endpoints.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-003 - iam:PassRole + glue:CreateJob + glue:StartJobRun",
        link="https://pathfinding.cloud/paths/glue-003",
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

        // Find glue:CreateJob permission
        MATCH (principal)--(createjob_policy:AWSPolicy)--(stmt_createjob:AWSPolicyStatement)
        WHERE stmt_createjob.effect = 'Allow'
            AND any(action IN stmt_createjob.action WHERE
                toLower(action) = 'glue:createjob'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find glue:StartJobRun permission
        MATCH (principal)--(startjob_policy:AWSPolicy)--(stmt_startjob:AWSPolicyStatement)
        WHERE stmt_startjob.effect = 'Allow'
            AND any(action IN stmt_startjob.action WHERE
                toLower(action) = 'glue:startjobrun'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (can be passed to Glue jobs)
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

# GLUE-004
AWS_GLUE_PRIVESC_PASSROLE_CREATE_JOB_TRIGGER = AttackPathsQueryDefinition(
    id="aws-glue-privesc-passrole-create-job-trigger",
    name="Glue Job Creation with Scheduled Trigger and Privileged Role (GLUE-004)",
    short_description="Create a Glue job with a privileged role and a scheduled trigger to persistently execute arbitrary code.",
    description="Detect principals who can pass IAM roles, create Glue jobs, and create triggers with automatic activation. Unlike manual execution via StartJobRun, this creates a persistent attack by scheduling the job to run repeatedly, making it harder to detect and remediate.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-004 - iam:PassRole + glue:CreateJob + glue:CreateTrigger",
        link="https://pathfinding.cloud/paths/glue-004",
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

        // Find glue:CreateJob permission
        MATCH (principal)--(createjob_policy:AWSPolicy)--(stmt_createjob:AWSPolicyStatement)
        WHERE stmt_createjob.effect = 'Allow'
            AND any(action IN stmt_createjob.action WHERE
                toLower(action) = 'glue:createjob'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find glue:CreateTrigger permission
        MATCH (principal)--(trigger_policy:AWSPolicy)--(stmt_trigger:AWSPolicyStatement)
        WHERE stmt_trigger.effect = 'Allow'
            AND any(action IN stmt_trigger.action WHERE
                toLower(action) = 'glue:createtrigger'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (can be passed to Glue jobs)
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

# GLUE-005
AWS_GLUE_PRIVESC_PASSROLE_UPDATE_JOB = AttackPathsQueryDefinition(
    id="aws-glue-privesc-passrole-update-job",
    name="Glue Job Hijacking via Update with Privileged Role (GLUE-005)",
    short_description="Update an existing Glue job to attach a privileged role and inject malicious code, then start it to gain that role's permissions.",
    description="Detect principals who can pass IAM roles, update existing Glue jobs, and start job runs. This allows modifying an existing job's role and script to execute arbitrary code with elevated privileges, a stealthier variant of job creation since it reuses existing infrastructure rather than creating new resources.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-005 - iam:PassRole + glue:UpdateJob + glue:StartJobRun",
        link="https://pathfinding.cloud/paths/glue-005",
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

        // Find glue:UpdateJob permission
        MATCH (principal)--(updatejob_policy:AWSPolicy)--(stmt_updatejob:AWSPolicyStatement)
        WHERE stmt_updatejob.effect = 'Allow'
            AND any(action IN stmt_updatejob.action WHERE
                toLower(action) = 'glue:updatejob'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find glue:StartJobRun permission
        MATCH (principal)--(startjob_policy:AWSPolicy)--(stmt_startjob:AWSPolicyStatement)
        WHERE stmt_startjob.effect = 'Allow'
            AND any(action IN stmt_startjob.action WHERE
                toLower(action) = 'glue:startjobrun'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (can be passed to Glue jobs)
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

# GLUE-006
AWS_GLUE_PRIVESC_PASSROLE_UPDATE_JOB_TRIGGER = AttackPathsQueryDefinition(
    id="aws-glue-privesc-passrole-update-job-trigger",
    name="Glue Job Hijacking with Scheduled Trigger and Privileged Role (GLUE-006)",
    short_description="Update an existing Glue job to attach a privileged role and inject malicious code, then create a scheduled trigger for persistent automated execution.",
    description="Detect principals who can pass IAM roles, update existing Glue jobs, and create triggers with automatic activation. This combines the stealth of modifying existing infrastructure with the persistence of scheduled automation, creating a recurring backdoor that re-executes even after remediation attempts.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - GLUE-006 - iam:PassRole + glue:UpdateJob + glue:CreateTrigger",
        link="https://pathfinding.cloud/paths/glue-006",
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

        // Find glue:UpdateJob permission
        MATCH (principal)--(updatejob_policy:AWSPolicy)--(stmt_updatejob:AWSPolicyStatement)
        WHERE stmt_updatejob.effect = 'Allow'
            AND any(action IN stmt_updatejob.action WHERE
                toLower(action) = 'glue:updatejob'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find glue:CreateTrigger permission
        MATCH (principal)--(trigger_policy:AWSPolicy)--(stmt_trigger:AWSPolicyStatement)
        WHERE stmt_trigger.effect = 'Allow'
            AND any(action IN stmt_trigger.action WHERE
                toLower(action) = 'glue:createtrigger'
                OR toLower(action) = 'glue:*'
                OR action = '*'
            )

        // Find roles that trust Glue service (can be passed to Glue jobs)
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

# IAM-001
AWS_IAM_PRIVESC_CREATE_POLICY_VERSION = AttackPathsQueryDefinition(
    id="aws-iam-privesc-create-policy-version",
    name="Policy Version Override for Self-Escalation (IAM-001)",
    short_description="Create a new version of an attached policy with administrative permissions, instantly escalating the principal's own privileges.",
    description="Detect principals who can create new policy versions. If a customer-managed policy is already attached to a principal and that principal has iam:CreatePolicyVersion on that policy, they can replace its contents with a fully permissive policy and set it as the default, gaining immediate administrative access.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-001 - iam:CreatePolicyVersion",
        link="https://pathfinding.cloud/paths/iam-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreatePolicyVersion permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createpolicyversion'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find customer-managed policies attached to the same principal that can be overwritten
        MATCH path_target = (aws)--(target_policy:AWSPolicy)--(principal)
        WHERE target_policy.arn CONTAINS $provider_uid
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR target_policy.arn CONTAINS resource
            )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-002
AWS_IAM_PRIVESC_CREATE_ACCESS_KEY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-create-access-key",
    name="Access Key Creation for Lateral Movement (IAM-002)",
    short_description="Create access keys for other IAM users to gain their permissions and move laterally across the account.",
    description="Detect principals who can create access keys for other IAM users. This allows generating new credentials for any target user within the resource scope, immediately gaining that user's permissions without needing their password or existing keys.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-002 - iam:CreateAccessKey",
        link="https://pathfinding.cloud/paths/iam-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreateAccessKey permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createaccesskey'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users that the principal can create access keys for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-003
AWS_IAM_PRIVESC_DELETE_CREATE_ACCESS_KEY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-delete-create-access-key",
    name="Access Key Rotation Attack for Lateral Movement (IAM-003)",
    short_description="Delete and recreate access keys for other IAM users to bypass the two-key limit and gain their permissions.",
    description="Detect principals who can both delete and create access keys for other IAM users. This variation of IAM-002 handles the scenario where a target user already has the maximum of two access keys by first deleting one, then creating a replacement under the attacker's control.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-003 - iam:CreateAccessKey + iam:DeleteAccessKey",
        link="https://pathfinding.cloud/paths/iam-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreateAccessKey permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createaccesskey'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:DeleteAccessKey permission
        MATCH (principal)--(delete_policy:AWSPolicy)--(stmt_delete:AWSPolicyStatement)
        WHERE stmt_delete.effect = 'Allow'
            AND any(action IN stmt_delete.action WHERE
                toLower(action) = 'iam:deleteaccesskey'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users that the principal can rotate access keys for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )
            AND any(resource IN stmt_delete.resource WHERE
                resource = '*'
                OR target_user.arn CONTAINS resource
                OR resource CONTAINS target_user.name
            )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-004
AWS_IAM_PRIVESC_CREATE_LOGIN_PROFILE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-create-login-profile",
    name="Console Login Profile Creation for Lateral Movement (IAM-004)",
    short_description="Create console login profiles for other IAM users to access the AWS Console with their permissions.",
    description="Detect principals who can create console login profiles for other IAM users. By setting a known password on a target user that lacks a login profile, the attacker gains AWS Console access with that user's permissions without needing their existing credentials.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-004 - iam:CreateLoginProfile",
        link="https://pathfinding.cloud/paths/iam-004",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreateLoginProfile permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createloginprofile'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users that the principal can create login profiles for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-005
AWS_IAM_PRIVESC_PUT_ROLE_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-role-policy",
    name="Inline Policy Injection for Self-Escalation (IAM-005)",
    short_description="Attach an inline policy with administrative permissions to your own role, instantly escalating privileges.",
    description="Detect roles that can use iam:PutRolePolicy on themselves. A role with this permission can attach an inline policy granting any permissions, including full administrative access, without needing to modify or assume any other resource.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-005 - iam:PutRolePolicy",
        link="https://pathfinding.cloud/paths/iam-005",
    ),
    provider="aws",
    cypher=f"""
        // Find roles with iam:PutRolePolicy permission scoped to themselves
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(role:AWSRole)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR role.arn CONTAINS resource
                OR resource CONTAINS role.name
            )

        UNWIND nodes(path_principal) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-006
AWS_IAM_PRIVESC_UPDATE_LOGIN_PROFILE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-update-login-profile",
    name="Console Password Override for Lateral Movement (IAM-006)",
    short_description="Change the console password of other IAM users to log in as them and gain their permissions.",
    description="Detect principals who can update console login profiles for other IAM users. By resetting a target user's password, the attacker gains AWS Console access with that user's permissions. Unlike IAM-004, this targets users who already have a login profile configured.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-006 - iam:UpdateLoginProfile",
        link="https://pathfinding.cloud/paths/iam-006",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:UpdateLoginProfile permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:updateloginprofile'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users that the principal can update login profiles for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-007
AWS_IAM_PRIVESC_PUT_USER_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-user-policy",
    name="Inline Policy Injection on User for Self-Escalation (IAM-007)",
    short_description="Attach an inline policy with administrative permissions to your own IAM user, instantly escalating privileges.",
    description="Detect IAM users that can use iam:PutUserPolicy on themselves. A user with this permission can attach an inline policy granting any permissions, including full administrative access, without needing to modify or assume any other resource. This is the user equivalent of IAM-005 (PutRolePolicy).",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-007 - iam:PutUserPolicy",
        link="https://pathfinding.cloud/paths/iam-007",
    ),
    provider="aws",
    cypher=f"""
        // Find users with iam:PutUserPolicy permission scoped to themselves
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(user:AWSUser)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putuserpolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR user.arn CONTAINS resource
                OR resource CONTAINS user.name
            )

        UNWIND nodes(path_principal) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-008
AWS_IAM_PRIVESC_ATTACH_USER_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-user-policy",
    name="Managed Policy Attachment on User for Self-Escalation (IAM-008)",
    short_description="Attach existing managed policies with administrative permissions to your own IAM user, instantly escalating privileges.",
    description="Detect IAM users that can use iam:AttachUserPolicy on themselves. A user with this permission can attach any existing managed policy, including AdministratorAccess, to themselves without needing to modify or assume any other resource. Unlike IAM-007 (PutUserPolicy), this requires an existing managed policy with elevated permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-008 - iam:AttachUserPolicy",
        link="https://pathfinding.cloud/paths/iam-008",
    ),
    provider="aws",
    cypher=f"""
        // Find users with iam:AttachUserPolicy permission scoped to themselves
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(user:AWSUser)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachuserpolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR user.arn CONTAINS resource
                OR resource CONTAINS user.name
            )

        UNWIND nodes(path_principal) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-009
AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-role-policy",
    name="Managed Policy Attachment on Role for Self-Escalation (IAM-009)",
    short_description="Attach existing managed policies with administrative permissions to your own IAM role, instantly escalating privileges.",
    description="Detect IAM roles that can use iam:AttachRolePolicy on themselves. A role with this permission can attach any existing managed policy, including AdministratorAccess, to itself without needing to modify or assume any other resource. Unlike IAM-005 (PutRolePolicy), this requires an existing managed policy with elevated permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-009 - iam:AttachRolePolicy",
        link="https://pathfinding.cloud/paths/iam-009",
    ),
    provider="aws",
    cypher=f"""
        // Find roles with iam:AttachRolePolicy permission scoped to themselves
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(role:AWSRole)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR role.arn CONTAINS resource
                OR resource CONTAINS role.name
            )

        UNWIND nodes(path_principal) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-010
AWS_IAM_PRIVESC_ATTACH_GROUP_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-group-policy",
    name="Managed Policy Attachment on Group for Self-Escalation (IAM-010)",
    short_description="Attach existing managed policies with administrative permissions to a group you belong to, escalating privileges for all group members.",
    description="Detect IAM users that can use iam:AttachGroupPolicy on a group they are a member of. A user with this permission can attach any existing managed policy, including AdministratorAccess, to a group they belong to, immediately escalating privileges for all group members.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-010 - iam:AttachGroupPolicy",
        link="https://pathfinding.cloud/paths/iam-010",
    ),
    provider="aws",
    cypher=f"""
        // Find users with iam:AttachGroupPolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(user:AWSUser)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachgrouppolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find groups the user is a member of and can attach policies to
        MATCH path_target = (aws)-[:RESOURCE]->(target_group:AWSGroup)<-[:MEMBER_AWS_GROUP]-(user)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_group.arn CONTAINS resource
            OR resource CONTAINS target_group.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-011
AWS_IAM_PRIVESC_PUT_GROUP_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-group-policy",
    name="Inline Policy Injection on Group for Self-Escalation (IAM-011)",
    short_description="Attach an inline policy with administrative permissions to a group you belong to, escalating privileges for all group members.",
    description="Detect IAM users that can use iam:PutGroupPolicy on a group they are a member of. A user with this permission can attach an inline policy granting any permissions to a group they belong to, immediately escalating privileges for all group members. Unlike IAM-010, this does not require an existing managed policy.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-011 - iam:PutGroupPolicy",
        link="https://pathfinding.cloud/paths/iam-011",
    ),
    provider="aws",
    cypher=f"""
        // Find users with iam:PutGroupPolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(user:AWSUser)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putgrouppolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find groups the user is a member of and can put policies on
        MATCH path_target = (aws)-[:RESOURCE]->(target_group:AWSGroup)<-[:MEMBER_AWS_GROUP]-(user)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_group.arn CONTAINS resource
            OR resource CONTAINS target_group.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-012
AWS_IAM_PRIVESC_UPDATE_ASSUME_ROLE_POLICY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-update-assume-role-policy",
    name="Trust Policy Hijacking for Role Assumption (IAM-012)",
    short_description="Modify a role's trust policy to allow yourself to assume it, gaining the role's permissions.",
    description="Detect principals who can update the assume role policy (trust policy) of other IAM roles. By modifying a target role's trust policy to trust the attacker's principal, the attacker can then assume the role and gain all its permissions, including potential administrative access.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-012 - iam:UpdateAssumeRolePolicy",
        link="https://pathfinding.cloud/paths/iam-012",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:UpdateAssumeRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:updateassumerolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles whose trust policy can be modified
        MATCH path_target = (aws)--(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
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

# IAM-013
AWS_IAM_PRIVESC_ADD_USER_TO_GROUP = AttackPathsQueryDefinition(
    id="aws-iam-privesc-add-user-to-group",
    name="Group Membership Hijacking for Privilege Escalation (IAM-013)",
    short_description="Add yourself to a privileged IAM group to inherit its permissions, gaining access to all policies attached to the group.",
    description="Detect principals who can add users to IAM groups. By adding themselves to a group with elevated permissions such as AdministratorAccess, the attacker immediately inherits all policies attached to that group. The level of access gained depends on the permissions of the target group.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-013 - iam:AddUserToGroup",
        link="https://pathfinding.cloud/paths/iam-013",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:AddUserToGroup permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:addusertogroup'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target groups the principal can add users to
        MATCH path_target = (aws)-[:RESOURCE]->(target_group:AWSGroup)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_group.arn CONTAINS resource
            OR resource CONTAINS target_group.name
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
    name="Managed Policy Attachment with Role Assumption for Lateral Movement (IAM-014)",
    short_description="Attach administrative managed policies to another role you can assume, then assume it to gain elevated privileges.",
    description="Detect principals who can attach managed policies to a different IAM role and also assume that role. By attaching AdministratorAccess to a target role and then assuming it, the attacker gains full administrative access. This is a variation of IAM-009 for lateral movement where the principal targets another assumable role instead of their own.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-014 - iam:AttachRolePolicy + sts:AssumeRole",
        link="https://pathfinding.cloud/paths/iam-014",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:AttachRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles the principal can assume and attach policies to
        MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
        WHERE any(resource IN stmt.resource WHERE
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

# IAM-015
AWS_IAM_PRIVESC_ATTACH_USER_POLICY_CREATE_ACCESS_KEY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-user-policy-create-access-key",
    name="Managed Policy Attachment with Access Key Creation for Lateral Movement (IAM-015)",
    short_description="Attach administrative managed policies to another IAM user and create access keys for them to gain programmatic access with elevated privileges.",
    description="Detect principals who can attach managed policies to another IAM user and also create access keys for that user. By attaching AdministratorAccess to a target user and creating access keys, the attacker gains programmatic access with the target user's elevated permissions. This combines IAM-008 (AttachUserPolicy) with IAM-002 (CreateAccessKey) for lateral movement.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-015 - iam:AttachUserPolicy + iam:CreateAccessKey",
        link="https://pathfinding.cloud/paths/iam-015",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:AttachUserPolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachuserpolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:CreateAccessKey permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'iam:createaccesskey'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users the principal can attach policies to and create keys for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )
        AND any(resource IN stmt2.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-016
AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-create-policy-version-assume-role",
    name="Policy Version Override with Role Assumption for Lateral Movement (IAM-016)",
    short_description="Create a new version of a customer-managed policy attached to another role with administrative permissions, then assume that role to gain elevated access.",
    description="Detect principals who can create new versions of customer-managed policies attached to other roles and also assume those roles. By creating a new policy version with administrative permissions on a policy attached to a target role, then assuming that role, the attacker gains full administrative access. This is a variation of IAM-001 for lateral movement where the modified policy is attached to an assumable role rather than the attacker's own principal.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-016 - iam:CreatePolicyVersion + sts:AssumeRole",
        link="https://pathfinding.cloud/paths/iam-016",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreatePolicyVersion permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createpolicyversion'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles the principal can assume that have customer-managed policies the principal can modify
        MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
        MATCH (target_role)--(target_policy:AWSPolicy)
        WHERE target_policy.arn CONTAINS $provider_uid
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR target_policy.arn CONTAINS resource
            )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-017
AWS_IAM_PRIVESC_PUT_ROLE_POLICY_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-role-policy-assume-role",
    name="Inline Policy Injection with Role Assumption for Lateral Movement (IAM-017)",
    short_description="Attach an inline policy with administrative permissions to another role you can assume, then assume it to gain elevated privileges.",
    description="Detect principals who can add inline policies to a different IAM role and also assume that role. By adding an inline policy granting administrative permissions to a target role and then assuming it, the attacker gains full administrative access. This is a variation of IAM-005 for lateral movement where the principal targets another assumable role instead of their own.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-017 - iam:PutRolePolicy + sts:AssumeRole",
        link="https://pathfinding.cloud/paths/iam-017",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PutRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles the principal can assume and put inline policies on
        MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
        WHERE any(resource IN stmt.resource WHERE
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

# IAM-018
AWS_IAM_PRIVESC_PUT_USER_POLICY_CREATE_ACCESS_KEY = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-user-policy-create-access-key",
    name="Inline Policy Injection with Access Key Creation for Lateral Movement (IAM-018)",
    short_description="Attach an inline policy with administrative permissions to another IAM user and create access keys for them to gain programmatic access with elevated privileges.",
    description="Detect principals who can add inline policies to another IAM user and also create access keys for that user. By adding an administrative inline policy to a target user and creating access keys, the attacker gains programmatic access with the target user's elevated permissions. This combines IAM-007 (PutUserPolicy) with IAM-002 (CreateAccessKey) for lateral movement.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-018 - iam:PutUserPolicy + iam:CreateAccessKey",
        link="https://pathfinding.cloud/paths/iam-018",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PutUserPolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putuserpolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:CreateAccessKey permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'iam:createaccesskey'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target users the principal can put policies on and create keys for
        MATCH path_target = (aws)--(target_user:AWSUser)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )
        AND any(resource IN stmt2.resource WHERE
            resource = '*'
            OR target_user.arn CONTAINS resource
            OR resource CONTAINS target_user.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-019
AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_UPDATE_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-attach-role-policy-update-assume-role",
    name="Managed Policy Attachment with Trust Policy Hijacking for Privilege Escalation (IAM-019)",
    short_description="Attach administrative managed policies to a role and modify its trust policy to allow yourself to assume it, gaining elevated privileges without prior assume-role access.",
    description="Detect principals who can attach managed policies to an IAM role and also update that role's trust policy. By attaching AdministratorAccess and modifying the trust policy to allow the attacker, the principal can then assume the role without needing pre-existing sts:AssumeRole permission. This combines IAM-009 (AttachRolePolicy) with IAM-012 (UpdateAssumeRolePolicy).",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-019 - iam:AttachRolePolicy + iam:UpdateAssumeRolePolicy",
        link="https://pathfinding.cloud/paths/iam-019",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:AttachRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:attachrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:UpdateAssumeRolePolicy permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'iam:updateassumerolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles the principal can attach policies to and update trust policy for
        MATCH path_target = (aws)--(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )
        AND any(resource IN stmt2.resource WHERE
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

# IAM-020
AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_UPDATE_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-create-policy-version-update-assume-role",
    name="Policy Version Override with Trust Policy Hijacking for Privilege Escalation (IAM-020)",
    short_description="Create a new version of a customer-managed policy attached to a role with administrative permissions and modify its trust policy to assume it, without prior assume-role access.",
    description="Detect principals who can create new versions of customer-managed policies attached to roles and also update those roles' trust policies. By creating an administrative policy version and modifying the trust policy to allow the attacker, the principal can assume the role without needing pre-existing sts:AssumeRole permission. This combines IAM-001 (CreatePolicyVersion) with IAM-012 (UpdateAssumeRolePolicy).",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-020 - iam:CreatePolicyVersion + iam:UpdateAssumeRolePolicy",
        link="https://pathfinding.cloud/paths/iam-020",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:CreatePolicyVersion permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:createpolicyversion'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:UpdateAssumeRolePolicy permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'iam:updateassumerolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles with customer-managed policies the principal can modify and update trust policy for
        MATCH path_target = (aws)--(target_role:AWSRole)
        WHERE any(resource IN stmt2.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )
        MATCH (target_role)--(target_policy:AWSPolicy)
        WHERE target_policy.arn CONTAINS $provider_uid
            AND any(resource IN stmt.resource WHERE
                resource = '*'
                OR target_policy.arn CONTAINS resource
            )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# IAM-021
AWS_IAM_PRIVESC_PUT_ROLE_POLICY_UPDATE_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-iam-privesc-put-role-policy-update-assume-role",
    name="Inline Policy Injection with Trust Policy Hijacking for Privilege Escalation (IAM-021)",
    short_description="Add an inline policy with administrative permissions to a role and modify its trust policy to allow yourself to assume it, gaining elevated privileges without prior assume-role access.",
    description="Detect principals who can add inline policies to an IAM role and also update that role's trust policy. By adding an administrative inline policy and modifying the trust policy to allow the attacker, the principal can then assume the role without needing pre-existing sts:AssumeRole permission. This combines IAM-005 (PutRolePolicy) with IAM-012 (UpdateAssumeRolePolicy).",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - IAM-021 - iam:PutRolePolicy + iam:UpdateAssumeRolePolicy",
        link="https://pathfinding.cloud/paths/iam-021",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with iam:PutRolePolicy permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'iam:putrolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find iam:UpdateAssumeRolePolicy permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'iam:updateassumerolepolicy'
                OR toLower(action) = 'iam:*'
                OR action = '*'
            )

        // Find target roles the principal can put inline policies on and update trust policy for
        MATCH path_target = (aws)--(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR target_role.arn CONTAINS resource
            OR resource CONTAINS target_role.name
        )
        AND any(resource IN stmt2.resource WHERE
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

# LAMBDA-001
AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-passrole-create-function",
    name="Lambda Function Creation with Privileged Role (LAMBDA-001)",
    short_description="Create a Lambda function with a privileged IAM role and invoke it to execute code with that role's permissions.",
    description="Detect principals who can create Lambda functions with privileged IAM roles and invoke them. By passing a privileged role to a new Lambda function and invoking it, the attacker executes code with the role's permissions, gaining access to any resources the role can access.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-001 - iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
        link="https://pathfinding.cloud/paths/lambda-001",
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

        // Find lambda:CreateFunction permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'lambda:createfunction'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find lambda:InvokeFunction permission
        MATCH (principal)--(invoke_policy:AWSPolicy)--(stmt_invoke:AWSPolicyStatement)
        WHERE stmt_invoke.effect = 'Allow'
            AND any(action IN stmt_invoke.action WHERE
                toLower(action) = 'lambda:invokefunction'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find roles that trust Lambda service (can be passed to Lambda)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'lambda.amazonaws.com'}})
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

# LAMBDA-002
AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION_EVENT_SOURCE = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-passrole-create-function-event-source",
    name="Lambda Function Creation with Event Source Trigger (LAMBDA-002)",
    short_description="Create a Lambda function with a privileged IAM role and an event source mapping to trigger it automatically, executing code with the role's permissions.",
    description="Detect principals who can create Lambda functions with privileged IAM roles and configure event source mappings to trigger them. By passing a privileged role to a new Lambda function and creating an event source mapping (DynamoDB stream, Kinesis, SQS), the attacker executes code with elevated privileges without needing to invoke the function directly.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-002 - iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping",
        link="https://pathfinding.cloud/paths/lambda-002",
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

        // Find lambda:CreateFunction permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'lambda:createfunction'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find lambda:CreateEventSourceMapping permission
        MATCH (principal)--(event_policy:AWSPolicy)--(stmt_event:AWSPolicyStatement)
        WHERE stmt_event.effect = 'Allow'
            AND any(action IN stmt_event.action WHERE
                toLower(action) = 'lambda:createeventsourcemapping'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find roles that trust Lambda service (can be passed to Lambda)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'lambda.amazonaws.com'}})
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

# LAMBDA-003
AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-update-function-code",
    name="Lambda Function Code Injection (LAMBDA-003)",
    short_description="Modify the code of an existing Lambda function to execute arbitrary commands with the function's execution role permissions.",
    description="Detect principals who can update the code of existing Lambda functions. By replacing a Lambda function's code with malicious code, the attacker executes arbitrary commands with the privileges of the function's execution role when it is next invoked, either manually or via automatic triggers.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-003 - lambda:UpdateFunctionCode",
        link="https://pathfinding.cloud/paths/lambda-003",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with lambda:UpdateFunctionCode permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'lambda:updatefunctioncode'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find existing Lambda functions with execution roles
        MATCH path_target = (aws)-[:RESOURCE]->(lambda_fn:AWSLambda)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR lambda_fn.arn CONTAINS resource
            OR resource CONTAINS lambda_fn.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# LAMBDA-004
AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE_INVOKE = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-update-function-code-invoke",
    name="Lambda Function Code Injection with Direct Invocation (LAMBDA-004)",
    short_description="Modify the code of an existing Lambda function and invoke it directly to execute arbitrary commands with the function's execution role permissions.",
    description="Detect principals who can update the code of existing Lambda functions and invoke them. By replacing a Lambda function's code with malicious code and invoking it directly, the attacker executes arbitrary commands with the privileges of the function's execution role immediately, without waiting for automatic triggers.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-004 - lambda:UpdateFunctionCode + lambda:InvokeFunction",
        link="https://pathfinding.cloud/paths/lambda-004",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with lambda:UpdateFunctionCode permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'lambda:updatefunctioncode'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find lambda:InvokeFunction permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'lambda:invokefunction'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find existing Lambda functions with execution roles
        MATCH path_target = (aws)-[:RESOURCE]->(lambda_fn:AWSLambda)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR lambda_fn.arn CONTAINS resource
            OR resource CONTAINS lambda_fn.name
        )
        AND any(resource IN stmt2.resource WHERE
            resource = '*'
            OR lambda_fn.arn CONTAINS resource
            OR resource CONTAINS lambda_fn.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# LAMBDA-005
AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE_ADD_PERMISSION = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-update-function-code-add-permission",
    name="Lambda Function Code Injection with Resource Policy Grant (LAMBDA-005)",
    short_description="Modify the code of an existing Lambda function and grant yourself invocation permission via its resource-based policy to execute code with the function's execution role.",
    description="Detect principals who can update the code of existing Lambda functions and add permissions to their resource-based policies. By replacing a Lambda function's code and granting themselves invoke access through the resource-based policy, the attacker executes malicious code with the function's execution role without needing lambda:InvokeFunction as an IAM permission.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-005 - lambda:UpdateFunctionCode + lambda:AddPermission",
        link="https://pathfinding.cloud/paths/lambda-005",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with lambda:UpdateFunctionCode permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'lambda:updatefunctioncode'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find lambda:AddPermission permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'lambda:addpermission'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find existing Lambda functions with execution roles
        MATCH path_target = (aws)-[:RESOURCE]->(lambda_fn:AWSLambda)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR lambda_fn.arn CONTAINS resource
            OR resource CONTAINS lambda_fn.name
        )
        AND any(resource IN stmt2.resource WHERE
            resource = '*'
            OR lambda_fn.arn CONTAINS resource
            OR resource CONTAINS lambda_fn.name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# LAMBDA-006
AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION_ADD_PERMISSION = AttackPathsQueryDefinition(
    id="aws-lambda-privesc-passrole-create-function-add-permission",
    name="Lambda Function Creation with Resource Policy Invocation (LAMBDA-006)",
    short_description="Create a Lambda function with a privileged IAM role and grant yourself invocation permission via its resource-based policy to execute code with the role's permissions.",
    description="Detect principals who can create Lambda functions with privileged IAM roles and add permissions to their resource-based policies. By passing a privileged role to a new Lambda function and granting themselves invoke access through the resource-based policy, the attacker executes malicious code with elevated privileges without needing lambda:InvokeFunction as an IAM permission.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - LAMBDA-006 - iam:PassRole + lambda:CreateFunction + lambda:AddPermission",
        link="https://pathfinding.cloud/paths/lambda-006",
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

        // Find lambda:CreateFunction permission
        MATCH (principal)--(create_policy:AWSPolicy)--(stmt_create:AWSPolicyStatement)
        WHERE stmt_create.effect = 'Allow'
            AND any(action IN stmt_create.action WHERE
                toLower(action) = 'lambda:createfunction'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find lambda:AddPermission permission
        MATCH (principal)--(perm_policy:AWSPolicy)--(stmt_perm:AWSPolicyStatement)
        WHERE stmt_perm.effect = 'Allow'
            AND any(action IN stmt_perm.action WHERE
                toLower(action) = 'lambda:addpermission'
                OR toLower(action) = 'lambda:*'
                OR action = '*'
            )

        // Find roles that trust Lambda service (can be passed to Lambda)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'lambda.amazonaws.com'}})
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

# SAGEMAKER-001
AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_NOTEBOOK = AttackPathsQueryDefinition(
    id="aws-sagemaker-privesc-passrole-create-notebook",
    name="SageMaker Notebook Creation with Privileged Role (SAGEMAKER-001)",
    short_description="Create a SageMaker notebook instance with a privileged IAM role to execute arbitrary code with the role's permissions via the Jupyter environment.",
    description="Detect principals who can create SageMaker notebook instances with privileged IAM roles. By passing a privileged role to a new notebook instance, the attacker gains shell access through the Jupyter environment and can execute arbitrary commands with the role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SAGEMAKER-001 - iam:PassRole + sagemaker:CreateNotebookInstance",
        link="https://pathfinding.cloud/paths/sagemaker-001",
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

        // Find sagemaker:CreateNotebookInstance permission
        MATCH (principal)--(sm_policy:AWSPolicy)--(stmt_sm:AWSPolicyStatement)
        WHERE stmt_sm.effect = 'Allow'
            AND any(action IN stmt_sm.action WHERE
                toLower(action) = 'sagemaker:createnotebookinstance'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find roles that trust SageMaker service (can be passed to SageMaker)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'sagemaker.amazonaws.com'}})
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

# SAGEMAKER-002
AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_TRAINING_JOB = AttackPathsQueryDefinition(
    id="aws-sagemaker-privesc-passrole-create-training-job",
    name="SageMaker Training Job Creation with Privileged Role (SAGEMAKER-002)",
    short_description="Create a SageMaker training job with a privileged IAM role to execute arbitrary container code with the role's permissions.",
    description="Detect principals who can create SageMaker training jobs with privileged IAM roles. By passing a privileged role to a new training job with a malicious training script or container, the attacker executes code with elevated privileges and can exfiltrate credentials or modify AWS resources.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SAGEMAKER-002 - iam:PassRole + sagemaker:CreateTrainingJob",
        link="https://pathfinding.cloud/paths/sagemaker-002",
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

        // Find sagemaker:CreateTrainingJob permission
        MATCH (principal)--(sm_policy:AWSPolicy)--(stmt_sm:AWSPolicyStatement)
        WHERE stmt_sm.effect = 'Allow'
            AND any(action IN stmt_sm.action WHERE
                toLower(action) = 'sagemaker:createtrainingjob'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find roles that trust SageMaker service (can be passed to SageMaker)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'sagemaker.amazonaws.com'}})
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

# SAGEMAKER-003
AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_PROCESSING_JOB = AttackPathsQueryDefinition(
    id="aws-sagemaker-privesc-passrole-create-processing-job",
    name="SageMaker Processing Job Creation with Privileged Role (SAGEMAKER-003)",
    short_description="Create a SageMaker processing job with a privileged IAM role to execute arbitrary container code with the role's permissions.",
    description="Detect principals who can create SageMaker processing jobs with privileged IAM roles. By passing a privileged role to a new processing job with a malicious script or container, the attacker executes code with elevated privileges and can exfiltrate credentials or modify AWS resources.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SAGEMAKER-003 - iam:PassRole + sagemaker:CreateProcessingJob",
        link="https://pathfinding.cloud/paths/sagemaker-003",
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

        // Find sagemaker:CreateProcessingJob permission
        MATCH (principal)--(sm_policy:AWSPolicy)--(stmt_sm:AWSPolicyStatement)
        WHERE stmt_sm.effect = 'Allow'
            AND any(action IN stmt_sm.action WHERE
                toLower(action) = 'sagemaker:createprocessingjob'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find roles that trust SageMaker service (can be passed to SageMaker)
        MATCH path_target = (aws)--(target_role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal {{arn: 'sagemaker.amazonaws.com'}})
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

# SAGEMAKER-004
AWS_SAGEMAKER_PRIVESC_PRESIGNED_NOTEBOOK_URL = AttackPathsQueryDefinition(
    id="aws-sagemaker-privesc-presigned-notebook-url",
    name="SageMaker Presigned Notebook URL for Privilege Escalation (SAGEMAKER-004)",
    short_description="Generate a presigned URL to access an existing SageMaker notebook instance and execute code with its execution role's permissions.",
    description="Detect principals who can generate presigned URLs to access existing SageMaker notebook instances. By accessing the Jupyter environment via a presigned URL, the attacker can execute arbitrary code with the permissions of the notebook's execution role without creating any new resources.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SAGEMAKER-004 - sagemaker:CreatePresignedNotebookInstanceUrl",
        link="https://pathfinding.cloud/paths/sagemaker-004",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with sagemaker:CreatePresignedNotebookInstanceUrl permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'sagemaker:createpresignednotebookinstanceurl'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find existing SageMaker notebook instances with execution roles
        MATCH path_target = (aws)-[:RESOURCE]->(notebook:AWSSageMakerNotebookInstance)-[:HAS_EXECUTION_ROLE]->(target_role:AWSRole)
        WHERE any(resource IN stmt.resource WHERE
            resource = '*'
            OR notebook.arn CONTAINS resource
            OR resource CONTAINS notebook.notebook_instance_name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# SAGEMAKER-005
AWS_SAGEMAKER_PRIVESC_LIFECYCLE_CONFIG_NOTEBOOK = AttackPathsQueryDefinition(
    id="aws-sagemaker-privesc-lifecycle-config-notebook",
    name="SageMaker Notebook Lifecycle Config Injection (SAGEMAKER-005)",
    short_description="Inject a malicious lifecycle configuration into an existing SageMaker notebook to execute code with the notebook's execution role during startup.",
    description="Detect principals who can inject malicious lifecycle configurations into existing SageMaker notebook instances. By stopping a notebook, attaching a malicious lifecycle config, and restarting it, the attacker executes arbitrary code with the notebook's execution role permissions during startup.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SAGEMAKER-005 - sagemaker:CreateNotebookInstanceLifecycleConfig + sagemaker:StopNotebookInstance + sagemaker:UpdateNotebookInstance + sagemaker:StartNotebookInstance",
        link="https://pathfinding.cloud/paths/sagemaker-005",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with sagemaker:CreateNotebookInstanceLifecycleConfig permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'sagemaker:createnotebookinstancelifecycleconfig'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find sagemaker:UpdateNotebookInstance permission
        MATCH (principal)--(policy2:AWSPolicy)--(stmt2:AWSPolicyStatement)
        WHERE stmt2.effect = 'Allow'
            AND any(action IN stmt2.action WHERE
                toLower(action) = 'sagemaker:updatenotebookinstance'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find sagemaker:StopNotebookInstance permission
        MATCH (principal)--(policy3:AWSPolicy)--(stmt3:AWSPolicyStatement)
        WHERE stmt3.effect = 'Allow'
            AND any(action IN stmt3.action WHERE
                toLower(action) = 'sagemaker:stopnotebookinstance'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find sagemaker:StartNotebookInstance permission
        MATCH (principal)--(policy4:AWSPolicy)--(stmt4:AWSPolicyStatement)
        WHERE stmt4.effect = 'Allow'
            AND any(action IN stmt4.action WHERE
                toLower(action) = 'sagemaker:startnotebookinstance'
                OR toLower(action) = 'sagemaker:*'
                OR action = '*'
            )

        // Find existing SageMaker notebook instances with execution roles
        MATCH path_target = (aws)-[:RESOURCE]->(notebook:AWSSageMakerNotebookInstance)-[:HAS_EXECUTION_ROLE]->(target_role:AWSRole)
        WHERE any(resource IN stmt2.resource WHERE
            resource = '*'
            OR notebook.arn CONTAINS resource
            OR resource CONTAINS notebook.notebook_instance_name
        )

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# SSM-001
AWS_SSM_PRIVESC_START_SESSION = AttackPathsQueryDefinition(
    id="aws-ssm-privesc-start-session",
    name="SSM Session Access for EC2 Role Credentials (SSM-001)",
    short_description="Start an SSM session on an EC2 instance to access its attached role credentials through IMDS.",
    description="Detect principals who can start SSM sessions on EC2 instances. This allows establishing a shell session on a running EC2 instance and retrieving the attached IAM role's temporary credentials from the Instance Metadata Service (IMDS), gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SSM-001 - ssm:StartSession",
        link="https://pathfinding.cloud/paths/ssm-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ssm:StartSession permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'ssm:startsession'
                OR toLower(action) = 'ssm:*'
                OR action = '*'
            )

        // Find EC2 instances with attached roles (targets for credential theft via IMDS)
        MATCH path_target = (aws)--(ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# SSM-002
AWS_SSM_PRIVESC_SEND_COMMAND = AttackPathsQueryDefinition(
    id="aws-ssm-privesc-send-command",
    name="SSM Send Command for EC2 Role Credentials (SSM-002)",
    short_description="Execute commands on an EC2 instance via SSM Run Command to access its attached role credentials through IMDS.",
    description="Detect principals who can send SSM commands to EC2 instances. This allows executing arbitrary commands on a running EC2 instance and retrieving the attached IAM role's temporary credentials from the Instance Metadata Service (IMDS), gaining that role's permissions.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - SSM-002 - ssm:SendCommand",
        link="https://pathfinding.cloud/paths/ssm-002",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with ssm:SendCommand permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'ssm:sendcommand'
                OR toLower(action) = 'ssm:*'
                OR action = '*'
            )

        // Find EC2 instances with attached roles (targets for credential theft via IMDS)
        MATCH path_target = (aws)--(ec2:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(target_role:AWSRole)

        UNWIND nodes(path_principal) + nodes(path_target) as n
        OPTIONAL MATCH (n)-[pfr]-(pf:{PROWLER_FINDING_LABEL} {{status: 'FAIL', provider_uid: $provider_uid}})

        RETURN path_principal, path_target,
            collect(DISTINCT pf) as dpf, collect(DISTINCT pfr) as dpfr
    """,
    parameters=[],
)

# STS-001
AWS_STS_PRIVESC_ASSUME_ROLE = AttackPathsQueryDefinition(
    id="aws-sts-privesc-assume-role",
    name="Role Assumption for Privilege Escalation (STS-001)",
    short_description="Assume IAM roles with elevated permissions by exploiting bidirectional trust between the starting principal and the target role.",
    description="Detect principals who can assume other IAM roles via sts:AssumeRole. When a principal has sts:AssumeRole permission and the target role's trust policy allows the principal to assume it (bidirectional trust), the attacker gains all permissions of the target role. This enables privilege escalation when the target role has higher privileges than the starting principal.",
    attribution=AttackPathsQueryAttribution(
        text="pathfinding.cloud - STS-001 - sts:AssumeRole",
        link="https://pathfinding.cloud/paths/sts-001",
    ),
    provider="aws",
    cypher=f"""
        // Find principals with sts:AssumeRole permission
        MATCH path_principal = (aws:AWSAccount {{id: $provider_uid}})--(principal:AWSPrincipal)--(policy:AWSPolicy)--(stmt:AWSPolicyStatement)
        WHERE stmt.effect = 'Allow'
            AND any(action IN stmt.action WHERE
                toLower(action) = 'sts:assumerole'
                OR toLower(action) = 'sts:*'
                OR action = '*'
            )

        // Find target roles the principal can assume (bidirectional trust via Cartography)
        MATCH path_target = (aws)--(target_role:AWSRole)<-[:STS_ASSUMEROLE_ALLOW]-(principal)
        WHERE any(resource IN stmt.resource WHERE
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
    AWS_APPRUNNER_PRIVESC_PASSROLE_CREATE_SERVICE,
    AWS_APPRUNNER_PRIVESC_UPDATE_SERVICE,
    AWS_BEDROCK_PRIVESC_PASSROLE_CODE_INTERPRETER,
    AWS_BEDROCK_PRIVESC_INVOKE_CODE_INTERPRETER,
    AWS_CLOUDFORMATION_PRIVESC_PASSROLE_CREATE_STACK,
    AWS_CLOUDFORMATION_PRIVESC_UPDATE_STACK,
    AWS_CLOUDFORMATION_PRIVESC_PASSROLE_CREATE_STACKSET,
    AWS_CLOUDFORMATION_PRIVESC_PASSROLE_UPDATE_STACKSET,
    AWS_CLOUDFORMATION_PRIVESC_CHANGESET,
    AWS_CODEBUILD_PRIVESC_PASSROLE_CREATE_PROJECT,
    AWS_CODEBUILD_PRIVESC_START_BUILD,
    AWS_CODEBUILD_PRIVESC_START_BUILD_BATCH,
    AWS_CODEBUILD_PRIVESC_PASSROLE_CREATE_PROJECT_BATCH,
    AWS_DATAPIPELINE_PRIVESC_PASSROLE_CREATE_PIPELINE,
    AWS_EC2_PRIVESC_PASSROLE_IAM,
    AWS_EC2_PRIVESC_MODIFY_INSTANCE_ATTRIBUTE,
    AWS_EC2_PRIVESC_PASSROLE_SPOT_INSTANCES,
    AWS_EC2_PRIVESC_LAUNCH_TEMPLATE,
    AWS_EC2INSTANCECONNECT_PRIVESC_SEND_SSH_PUBLIC_KEY,
    AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE,
    AWS_ECS_PRIVESC_PASSROLE_RUN_TASK,
    AWS_ECS_PRIVESC_PASSROLE_CREATE_SERVICE_EXISTING_CLUSTER,
    AWS_ECS_PRIVESC_PASSROLE_RUN_TASK_EXISTING_CLUSTER,
    AWS_ECS_PRIVESC_PASSROLE_START_TASK_EXISTING_CLUSTER,
    AWS_ECS_PRIVESC_EXECUTE_COMMAND,
    AWS_GLUE_PRIVESC_PASSROLE_DEV_ENDPOINT,
    AWS_GLUE_PRIVESC_UPDATE_DEV_ENDPOINT,
    AWS_GLUE_PRIVESC_PASSROLE_CREATE_JOB,
    AWS_GLUE_PRIVESC_PASSROLE_CREATE_JOB_TRIGGER,
    AWS_GLUE_PRIVESC_PASSROLE_UPDATE_JOB,
    AWS_GLUE_PRIVESC_PASSROLE_UPDATE_JOB_TRIGGER,
    AWS_IAM_PRIVESC_CREATE_POLICY_VERSION,
    AWS_IAM_PRIVESC_CREATE_ACCESS_KEY,
    AWS_IAM_PRIVESC_DELETE_CREATE_ACCESS_KEY,
    AWS_IAM_PRIVESC_CREATE_LOGIN_PROFILE,
    AWS_IAM_PRIVESC_PUT_ROLE_POLICY,
    AWS_IAM_PRIVESC_UPDATE_LOGIN_PROFILE,
    AWS_IAM_PRIVESC_PUT_USER_POLICY,
    AWS_IAM_PRIVESC_ATTACH_USER_POLICY,
    AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY,
    AWS_IAM_PRIVESC_ATTACH_GROUP_POLICY,
    AWS_IAM_PRIVESC_PUT_GROUP_POLICY,
    AWS_IAM_PRIVESC_UPDATE_ASSUME_ROLE_POLICY,
    AWS_IAM_PRIVESC_ADD_USER_TO_GROUP,
    AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_ASSUME_ROLE,
    AWS_IAM_PRIVESC_ATTACH_USER_POLICY_CREATE_ACCESS_KEY,
    AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_ASSUME_ROLE,
    AWS_IAM_PRIVESC_PUT_ROLE_POLICY_ASSUME_ROLE,
    AWS_IAM_PRIVESC_PUT_USER_POLICY_CREATE_ACCESS_KEY,
    AWS_IAM_PRIVESC_ATTACH_ROLE_POLICY_UPDATE_ASSUME_ROLE,
    AWS_IAM_PRIVESC_CREATE_POLICY_VERSION_UPDATE_ASSUME_ROLE,
    AWS_IAM_PRIVESC_PUT_ROLE_POLICY_UPDATE_ASSUME_ROLE,
    AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION,
    AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION_EVENT_SOURCE,
    AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE,
    AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE_INVOKE,
    AWS_LAMBDA_PRIVESC_UPDATE_FUNCTION_CODE_ADD_PERMISSION,
    AWS_LAMBDA_PRIVESC_PASSROLE_CREATE_FUNCTION_ADD_PERMISSION,
    AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_NOTEBOOK,
    AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_TRAINING_JOB,
    AWS_SAGEMAKER_PRIVESC_PASSROLE_CREATE_PROCESSING_JOB,
    AWS_SAGEMAKER_PRIVESC_PRESIGNED_NOTEBOOK_URL,
    AWS_SAGEMAKER_PRIVESC_LIFECYCLE_CONFIG_NOTEBOOK,
    AWS_SSM_PRIVESC_START_SESSION,
    AWS_SSM_PRIVESC_SEND_COMMAND,
    AWS_STS_PRIVESC_ASSUME_ROLE,
]
