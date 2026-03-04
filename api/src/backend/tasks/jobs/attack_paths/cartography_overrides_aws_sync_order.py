# TODO: Remove this file when Cartography fixes the RESOURCE_FUNCTIONS ordering.
# https://github.com/cartography-cncf/cartography/issues/XXXX
#
# Explicit sync order for cartography AWS resource functions.
# Based on cartography_aws.RESOURCE_FUNCTIONS (v0.129.0) with one change:
# ec2:security_group moved before ec2:load_balancer, ec2:load_balancer_v2,
# and ec2:network_interface. These resources use OPTIONAL MATCH to link to
# EC2SecurityGroup nodes. On a fresh database the target nodes must exist
# first, otherwise MEMBER_OF_EC2_SECURITY_GROUP edges are silently dropped
# and exposed_internet is never set.

AWS_SYNC_ORDER: list[str] = [
    "iam",
    "iaminstanceprofiles",
    "s3",
    "kms",
    "dynamodb",
    "ec2:launch_templates",
    "ec2:autoscalinggroup",
    "ec2:instance",
    "ec2:images",
    "ec2:keypair",
    "ec2:security_group",  # moved here (was after ec2:network_interface)
    "ec2:subnet",
    "ec2:load_balancer",  # depends on ec2:security_group
    "ec2:load_balancer_v2",  # depends on ec2:security_group
    "ec2:network_acls",
    "ec2:network_interface",  # depends on ec2:security_group
    "ec2:tgw",
    "ec2:vpc",
    "ec2:vpc_endpoint",
    "ec2:route_table",
    "ec2:vpc_peering",
    "ec2:internet_gateway",
    "ec2:reserved_instances",
    "ec2:volumes",
    "ec2:snapshots",
    "ecr",
    "ecr:image_layers",
    "ecs",
    "eks",
    "elasticache",
    "elastic_ip_addresses",
    "emr",
    "lambda_function",
    "rds",
    "redshift",
    "route53",
    "elasticsearch",
    "permission_relationships",
    "resourcegroupstaggingapi",
    "apigateway",
    "apigatewayv2",
    "bedrock",
    "cloudfront",
    "secretsmanager",
    "securityhub",
    "s3accountpublicaccessblock",
    "sagemaker",
    "sns",
    "sqs",
    "ssm",
    "acm:certificate",
    "inspector",
    "config",
    "identitycenter",
    "cloudtrail",
    "cloudtrail_management_events",
    "cloudwatch",
    "efs",
    "guardduty",
    "codebuild",
    "cognito",
    "eventbridge",
    "glue",
]
