"""CloudTrail enrichment service for Prowler findings.

This module queries AWS CloudTrail to enrich security findings with timeline
context showing who performed actions, what changed, and when events occurred.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from prowler.lib.logger import logger
from prowler.providers.aws.lib.cloudtrail_enrichment.formatters import (
    EventMessageFormatter,
)
from prowler.providers.aws.lib.cloudtrail_enrichment.models import (
    CloudTrailEventType,
    CloudWatchEventType,
    DynamoDBEventType,
    EBSEventType,
    EC2EventType,
    ECREventType,
    ECSEventType,
    ELBEventType,
    ELBv2EventType,
    GeneralEventType,
    IAMEventType,
    KMSEventType,
    LambdaEventType,
    RDSEventType,
    S3EventType,
    SecretsManagerEventType,
    SNSEventType,
    SQSEventType,
    TimelineEvent,
    VPCEventType,
)


class CloudTrailEnricher:
    """Enriches findings with CloudTrail event timeline.

    Queries CloudTrail to build a timeline of events for resources in findings,
    providing context about who created/modified resources and when.
    """

    # Event mappings for EC2 Instances
    EC2_INSTANCE_EVENTS = {
        "RunInstances": {
            "event_type": EC2EventType.INSTANCE_CREATED,
            "message": "Instance created",
            "formatter": EventMessageFormatter.format_instance_created,
        },
        "TerminateInstances": {
            "event_type": EC2EventType.INSTANCE_TERMINATED,
            "message": "Instance terminated",
        },
        "StartInstances": {
            "event_type": EC2EventType.INSTANCE_STARTED,
            "message": "Instance started",
        },
        "StopInstances": {
            "event_type": EC2EventType.INSTANCE_STOPPED,
            "message": "Instance stopped",
        },
        "RebootInstances": {
            "event_type": EC2EventType.INSTANCE_REBOOTED,
            "message": "Instance rebooted",
        },
    }

    # Event mappings for Security Groups
    SECURITY_GROUP_EVENTS = {
        "CreateSecurityGroup": {
            "event_type": EC2EventType.SECURITY_GROUP_CREATED,
            "message": "Security group created",
        },
        "AuthorizeSecurityGroupIngress": {
            "event_type": EC2EventType.SECURITY_GROUP_RULE_ADDED,
            "message": "Ingress rule added",
            "formatter": EventMessageFormatter.format_security_group_rule_added,
        },
        "ModifySecurityGroupRules": {
            "event_type": EC2EventType.SECURITY_GROUP_RULE_MODIFIED,
            "message": "Security group rules modified",
            "formatter": EventMessageFormatter.format_security_group_rule_modified,
        },
        "RevokeSecurityGroupIngress": {
            "event_type": EC2EventType.SECURITY_GROUP_RULE_REMOVED,
            "message": "Ingress rule removed",
            "formatter": EventMessageFormatter.format_security_group_rule_removed,
        },
    }

    # Event mappings for Network Interfaces
    NETWORK_INTERFACE_EVENTS = {
        "CreateNetworkInterface": {
            "event_type": EC2EventType.NETWORK_INTERFACE_CREATED,
            "message": "Network interface created",
        },
        "ModifyNetworkInterfaceAttribute": {
            "event_type": EC2EventType.NETWORK_INTERFACE_MODIFIED,
            "message": "Network interface modified",
            "formatter": EventMessageFormatter.format_eni_attribute_modification,
        },
        "AttachNetworkInterface": {
            "event_type": EC2EventType.NETWORK_INTERFACE_ATTACHED,
            "message": "Network interface attached",
        },
        "DetachNetworkInterface": {
            "event_type": EC2EventType.NETWORK_INTERFACE_DETACHED,
            "message": "Network interface detached",
        },
    }

    # Event mappings for Load Balancers
    LOAD_BALANCER_EVENTS = {
        "CreateLoadBalancer": {
            "event_type": ELBEventType.LOAD_BALANCER_CREATED,
            "message": "Load balancer created",
            "formatter": EventMessageFormatter.format_load_balancer_created,
        },
        "ModifyLoadBalancerAttributes": {
            "event_type": ELBEventType.LOAD_BALANCER_MODIFIED,
            "message": "Load balancer attributes modified",
        },
        "DeleteLoadBalancer": {
            "event_type": ELBEventType.LOAD_BALANCER_DELETED,
            "message": "Load balancer deleted",
        },
    }

    # Event mappings for RDS Instances
    RDS_INSTANCE_EVENTS = {
        "CreateDBInstance": {
            "event_type": RDSEventType.INSTANCE_CREATED,
            "message": "RDS instance created",
            "formatter": EventMessageFormatter.format_rds_instance_created,
        },
        "ModifyDBInstance": {
            "event_type": RDSEventType.INSTANCE_MODIFIED,
            "message": "RDS instance modified",
            "formatter": EventMessageFormatter.format_rds_instance_modified,
        },
        "DeleteDBInstance": {
            "event_type": RDSEventType.INSTANCE_DELETED,
            "message": "RDS instance deleted",
        },
        "CreateDBSnapshot": {
            "event_type": RDSEventType.SNAPSHOT_CREATED,
            "message": "RDS snapshot created",
        },
        "ModifyDBSnapshotAttribute": {
            "event_type": RDSEventType.SNAPSHOT_SHARED,
            "message": "RDS snapshot sharing modified",
            "formatter": EventMessageFormatter.format_rds_snapshot_shared,
        },
        "CreateDBCluster": {
            "event_type": RDSEventType.CLUSTER_CREATED,
            "message": "RDS cluster created",
        },
        "ModifyDBCluster": {
            "event_type": RDSEventType.CLUSTER_MODIFIED,
            "message": "RDS cluster modified",
        },
    }

    # Event mappings for S3 Buckets
    S3_BUCKET_EVENTS = {
        "CreateBucket": {
            "event_type": S3EventType.BUCKET_CREATED,
            "message": "S3 bucket created",
            "formatter": EventMessageFormatter.format_s3_bucket_created,
        },
        "DeleteBucket": {
            "event_type": S3EventType.BUCKET_DELETED,
            "message": "S3 bucket deleted",
        },
        "PutBucketPolicy": {
            "event_type": S3EventType.BUCKET_POLICY_CHANGED,
            "message": "S3 bucket policy changed",
            "formatter": EventMessageFormatter.format_s3_bucket_policy_changed,
        },
        "DeleteBucketPolicy": {
            "event_type": S3EventType.BUCKET_POLICY_CHANGED,
            "message": "S3 bucket policy deleted",
        },
        "PutPublicAccessBlock": {
            "event_type": S3EventType.PUBLIC_ACCESS_BLOCK_CHANGED,
            "message": "S3 public access block configuration changed",
            "formatter": EventMessageFormatter.format_s3_public_access_block_changed,
        },
        "DeletePublicAccessBlock": {
            "event_type": S3EventType.PUBLIC_ACCESS_BLOCK_CHANGED,
            "message": "S3 public access block removed",
        },
        "PutBucketEncryption": {
            "event_type": S3EventType.ENCRYPTION_CHANGED,
            "message": "S3 bucket encryption configured",
            "formatter": EventMessageFormatter.format_s3_encryption_changed,
        },
        "DeleteBucketEncryption": {
            "event_type": S3EventType.ENCRYPTION_CHANGED,
            "message": "S3 bucket encryption removed",
        },
        "PutBucketVersioning": {
            "event_type": S3EventType.VERSIONING_CHANGED,
            "message": "S3 bucket versioning changed",
        },
        "PutBucketLogging": {
            "event_type": S3EventType.LOGGING_CHANGED,
            "message": "S3 bucket logging configured",
        },
    }

    # Event mappings for Lambda Functions
    LAMBDA_FUNCTION_EVENTS = {
        "CreateFunction": {
            "event_type": LambdaEventType.FUNCTION_CREATED,
            "message": "Lambda function created",
            "formatter": EventMessageFormatter.format_lambda_function_created,
        },
        "DeleteFunction": {
            "event_type": LambdaEventType.FUNCTION_DELETED,
            "message": "Lambda function deleted",
        },
        "UpdateFunctionConfiguration": {
            "event_type": LambdaEventType.FUNCTION_UPDATED,
            "message": "Lambda function configuration updated",
        },
        "UpdateFunctionCode": {
            "event_type": LambdaEventType.CODE_UPDATED,
            "message": "Lambda function code updated",
            "formatter": EventMessageFormatter.format_lambda_code_updated,
        },
        "AddPermission": {
            "event_type": LambdaEventType.PERMISSION_ADDED,
            "message": "Lambda permission added",
            "formatter": EventMessageFormatter.format_lambda_permission_added,
        },
        "CreateFunctionUrlConfig": {
            "event_type": LambdaEventType.FUNCTION_URL_CREATED,
            "message": "Lambda function URL created",
            "formatter": EventMessageFormatter.format_lambda_function_url_created,
        },
        "UpdateFunctionUrlConfig": {
            "event_type": LambdaEventType.FUNCTION_URL_CREATED,
            "message": "Lambda function URL updated",
        },
    }

    # Event mappings for VPC Resources
    VPC_EVENTS = {
        "CreateVpc": {
            "event_type": VPCEventType.VPC_CREATED,
            "message": "VPC created",
        },
        "CreateSubnet": {
            "event_type": VPCEventType.SUBNET_CREATED,
            "message": "Subnet created",
            "formatter": EventMessageFormatter.format_subnet_created,
        },
        "ModifySubnetAttribute": {
            "event_type": VPCEventType.SUBNET_MODIFIED,
            "message": "Subnet modified",
            "formatter": EventMessageFormatter.format_subnet_modified,
        },
        "CreateRouteTable": {
            "event_type": VPCEventType.ROUTE_TABLE_CREATED,
            "message": "Route table created",
        },
        "CreateRoute": {
            "event_type": VPCEventType.ROUTE_CREATED,
            "message": "Route created",
            "formatter": EventMessageFormatter.format_route_created,
        },
        "CreateInternetGateway": {
            "event_type": VPCEventType.INTERNET_GATEWAY_CREATED,
            "message": "Internet gateway created",
        },
        "AttachInternetGateway": {
            "event_type": VPCEventType.INTERNET_GATEWAY_ATTACHED,
            "message": "Internet gateway attached",
            "formatter": EventMessageFormatter.format_internet_gateway_attached,
        },
        "CreateNatGateway": {
            "event_type": VPCEventType.NAT_GATEWAY_CREATED,
            "message": "NAT gateway created",
        },
        "CreateVpcEndpoint": {
            "event_type": VPCEventType.VPC_ENDPOINT_CREATED,
            "message": "VPC endpoint created",
            "formatter": EventMessageFormatter.format_vpc_endpoint_created,
        },
        "CreateNetworkAcl": {
            "event_type": VPCEventType.NETWORK_ACL_CREATED,
            "message": "Network ACL created",
        },
        "CreateNetworkAclEntry": {
            "event_type": VPCEventType.NETWORK_ACL_ENTRY_CREATED,
            "message": "Network ACL entry created",
        },
    }

    # Event mappings for ELBv2 (ALB/NLB)
    ELBV2_EVENTS = {
        "CreateLoadBalancer": {
            "event_type": ELBv2EventType.LOAD_BALANCER_CREATED,
            "message": "Load balancer created",
            "formatter": EventMessageFormatter.format_elbv2_load_balancer_created,
        },
        "ModifyLoadBalancerAttributes": {
            "event_type": ELBv2EventType.LOAD_BALANCER_MODIFIED,
            "message": "Load balancer attributes modified",
        },
        "DeleteLoadBalancer": {
            "event_type": ELBv2EventType.LOAD_BALANCER_DELETED,
            "message": "Load balancer deleted",
        },
        "CreateListener": {
            "event_type": ELBv2EventType.LISTENER_CREATED,
            "message": "Listener created",
            "formatter": EventMessageFormatter.format_elbv2_listener_created,
        },
        "ModifyListener": {
            "event_type": ELBv2EventType.LISTENER_MODIFIED,
            "message": "Listener modified",
        },
        "CreateTargetGroup": {
            "event_type": ELBv2EventType.TARGET_GROUP_CREATED,
            "message": "Target group created",
        },
    }

    # Event mappings for IAM
    IAM_EVENTS = {
        "CreateUser": {
            "event_type": IAMEventType.USER_CREATED,
            "message": "IAM user created",
            "formatter": EventMessageFormatter.format_iam_user_created,
        },
        "DeleteUser": {
            "event_type": IAMEventType.USER_DELETED,
            "message": "IAM user deleted",
        },
        "CreateRole": {
            "event_type": IAMEventType.ROLE_CREATED,
            "message": "IAM role created",
            "formatter": EventMessageFormatter.format_iam_role_created,
        },
        "DeleteRole": {
            "event_type": IAMEventType.ROLE_DELETED,
            "message": "IAM role deleted",
        },
        "AttachUserPolicy": {
            "event_type": IAMEventType.POLICY_ATTACHED,
            "message": "Policy attached to user",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "AttachRolePolicy": {
            "event_type": IAMEventType.POLICY_ATTACHED,
            "message": "Policy attached to role",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "AttachGroupPolicy": {
            "event_type": IAMEventType.POLICY_ATTACHED,
            "message": "Policy attached to group",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "CreatePolicy": {
            "event_type": IAMEventType.POLICY_CREATED,
            "message": "IAM policy created",
        },
        "CreateAccessKey": {
            "event_type": IAMEventType.ACCESS_KEY_CREATED,
            "message": "Access key created",
            "formatter": EventMessageFormatter.format_iam_access_key_created,
        },
        "AddUserToGroup": {
            "event_type": IAMEventType.USER_ADDED_TO_GROUP,
            "message": "User added to group",
        },
        "UpdateAssumeRolePolicy": {
            "event_type": IAMEventType.ASSUME_ROLE_POLICY_UPDATED,
            "message": "Assume role policy updated",
        },
    }

    # Event mappings for DynamoDB
    DYNAMODB_EVENTS = {
        "CreateTable": {
            "event_type": DynamoDBEventType.TABLE_CREATED,
            "message": "DynamoDB table created",
            "formatter": EventMessageFormatter.format_dynamodb_table_created,
        },
        "UpdateTable": {
            "event_type": DynamoDBEventType.TABLE_UPDATED,
            "message": "DynamoDB table updated",
        },
        "DeleteTable": {
            "event_type": DynamoDBEventType.TABLE_DELETED,
            "message": "DynamoDB table deleted",
        },
        "CreateBackup": {
            "event_type": DynamoDBEventType.BACKUP_CREATED,
            "message": "DynamoDB backup created",
        },
        "UpdateContinuousBackups": {
            "event_type": DynamoDBEventType.PITR_UPDATED,
            "message": "DynamoDB PITR configuration updated",
            "formatter": EventMessageFormatter.format_dynamodb_pitr_updated,
        },
    }

    # Event mappings for KMS
    KMS_EVENTS = {
        "CreateKey": {
            "event_type": KMSEventType.KEY_CREATED,
            "message": "KMS key created",
            "formatter": EventMessageFormatter.format_kms_key_created,
        },
        "ScheduleKeyDeletion": {
            "event_type": KMSEventType.KEY_DELETION_SCHEDULED,
            "message": "KMS key deletion scheduled",
            "formatter": EventMessageFormatter.format_kms_key_deletion_scheduled,
        },
        "CancelKeyDeletion": {
            "event_type": KMSEventType.KEY_DELETION_CANCELLED,
            "message": "KMS key deletion cancelled",
            "formatter": EventMessageFormatter.format_kms_key_deletion_cancelled,
        },
        "DisableKey": {
            "event_type": KMSEventType.KEY_DISABLED,
            "message": "KMS key disabled",
            "formatter": EventMessageFormatter.format_kms_key_disabled,
        },
        "EnableKey": {
            "event_type": KMSEventType.KEY_ENABLED,
            "message": "KMS key enabled",
            "formatter": EventMessageFormatter.format_kms_key_enabled,
        },
        "EnableKeyRotation": {
            "event_type": KMSEventType.KEY_ROTATION_ENABLED,
            "message": "KMS key rotation enabled",
            "formatter": EventMessageFormatter.format_kms_key_rotation_enabled,
        },
        "DisableKeyRotation": {
            "event_type": KMSEventType.KEY_ROTATION_DISABLED,
            "message": "KMS key rotation disabled",
            "formatter": EventMessageFormatter.format_kms_key_rotation_disabled,
        },
        "PutKeyPolicy": {
            "event_type": KMSEventType.KEY_POLICY_CHANGED,
            "message": "KMS key policy changed",
            "formatter": EventMessageFormatter.format_kms_key_policy_changed,
        },
        "ImportKeyMaterial": {
            "event_type": KMSEventType.KEY_IMPORTED,
            "message": "KMS key material imported",
            "formatter": EventMessageFormatter.format_kms_key_imported,
        },
        "CreateGrant": {
            "event_type": KMSEventType.GRANT_CREATED,
            "message": "KMS grant created",
            "formatter": EventMessageFormatter.format_kms_grant_created,
        },
        "RevokeGrant": {
            "event_type": KMSEventType.GRANT_REVOKED,
            "message": "KMS grant revoked",
            "formatter": EventMessageFormatter.format_kms_grant_revoked,
        },
    }

    # Event mappings for CloudTrail
    CLOUDTRAIL_EVENTS = {
        "CreateTrail": {
            "event_type": CloudTrailEventType.TRAIL_CREATED,
            "message": "CloudTrail trail created",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_created,
        },
        "DeleteTrail": {
            "event_type": CloudTrailEventType.TRAIL_DELETED,
            "message": "CloudTrail trail deleted",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_deleted,
        },
        "UpdateTrail": {
            "event_type": CloudTrailEventType.TRAIL_UPDATED,
            "message": "CloudTrail trail updated",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_updated,
        },
        "StopLogging": {
            "event_type": CloudTrailEventType.LOGGING_STOPPED,
            "message": "CloudTrail logging stopped",
            "formatter": EventMessageFormatter.format_cloudtrail_logging_stopped,
        },
        "StartLogging": {
            "event_type": CloudTrailEventType.LOGGING_STARTED,
            "message": "CloudTrail logging started",
            "formatter": EventMessageFormatter.format_cloudtrail_logging_started,
        },
        "PutEventSelectors": {
            "event_type": CloudTrailEventType.EVENT_SELECTORS_UPDATED,
            "message": "CloudTrail event selectors updated",
            "formatter": EventMessageFormatter.format_cloudtrail_event_selectors_updated,
        },
    }

    # Event mappings for EBS
    EBS_EVENTS = {
        "CreateVolume": {
            "event_type": EBSEventType.VOLUME_CREATED,
            "message": "EBS volume created",
            "formatter": EventMessageFormatter.format_ebs_volume_created,
        },
        "DeleteVolume": {
            "event_type": EBSEventType.VOLUME_DELETED,
            "message": "EBS volume deleted",
            "formatter": EventMessageFormatter.format_ebs_volume_deleted,
        },
        "ModifyVolume": {
            "event_type": EBSEventType.VOLUME_MODIFIED,
            "message": "EBS volume modified",
            "formatter": EventMessageFormatter.format_ebs_volume_modified,
        },
        "CreateSnapshot": {
            "event_type": EBSEventType.SNAPSHOT_CREATED,
            "message": "EBS snapshot created",
            "formatter": EventMessageFormatter.format_ebs_snapshot_created,
        },
        "DeleteSnapshot": {
            "event_type": EBSEventType.SNAPSHOT_DELETED,
            "message": "EBS snapshot deleted",
            "formatter": EventMessageFormatter.format_ebs_snapshot_deleted,
        },
        "ModifySnapshotAttribute": {
            "event_type": EBSEventType.SNAPSHOT_SHARED,
            "message": "EBS snapshot permissions modified",
            "formatter": EventMessageFormatter.format_ebs_snapshot_shared,
        },
        "EnableEbsEncryptionByDefault": {
            "event_type": EBSEventType.ENCRYPTION_ENABLED,
            "message": "EBS encryption by default enabled",
            "formatter": EventMessageFormatter.format_ebs_encryption_enabled,
        },
        "DisableEbsEncryptionByDefault": {
            "event_type": EBSEventType.ENCRYPTION_DISABLED,
            "message": "EBS encryption by default disabled",
            "formatter": EventMessageFormatter.format_ebs_encryption_disabled,
        },
    }

    # Event mappings for Secrets Manager
    SECRETS_MANAGER_EVENTS = {
        "CreateSecret": {
            "event_type": SecretsManagerEventType.SECRET_CREATED,
            "message": "Secret created",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_created,
        },
        "DeleteSecret": {
            "event_type": SecretsManagerEventType.SECRET_DELETED,
            "message": "Secret deleted",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_deleted,
        },
        "UpdateSecret": {
            "event_type": SecretsManagerEventType.SECRET_UPDATED,
            "message": "Secret updated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_updated,
        },
        "PutSecretValue": {
            "event_type": SecretsManagerEventType.SECRET_UPDATED,
            "message": "Secret value updated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_updated,
        },
        "RotateSecret": {
            "event_type": SecretsManagerEventType.SECRET_ROTATED,
            "message": "Secret rotated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_rotated,
        },
        "CancelRotateSecret": {
            "event_type": SecretsManagerEventType.ROTATION_DISABLED,
            "message": "Secret rotation disabled",
            "formatter": EventMessageFormatter.format_secrets_manager_rotation_disabled,
        },
        "PutResourcePolicy": {
            "event_type": SecretsManagerEventType.POLICY_CHANGED,
            "message": "Secret resource policy changed",
            "formatter": EventMessageFormatter.format_secrets_manager_policy_changed,
        },
    }

    # Event mappings for CloudWatch
    CLOUDWATCH_EVENTS = {
        "PutMetricAlarm": {
            "event_type": CloudWatchEventType.ALARM_CREATED,
            "message": "CloudWatch alarm created/updated",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_created,
        },
        "DeleteAlarms": {
            "event_type": CloudWatchEventType.ALARM_DELETED,
            "message": "CloudWatch alarm(s) deleted",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_deleted,
        },
        "SetAlarmState": {
            "event_type": CloudWatchEventType.ALARM_STATE_CHANGED,
            "message": "CloudWatch alarm state changed",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_state_changed,
        },
        "DisableAlarmActions": {
            "event_type": CloudWatchEventType.ALARM_ACTIONS_DISABLED,
            "message": "CloudWatch alarm actions disabled",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_actions_disabled,
        },
        "EnableAlarmActions": {
            "event_type": CloudWatchEventType.ALARM_ACTIONS_ENABLED,
            "message": "CloudWatch alarm actions enabled",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_actions_enabled,
        },
        "CreateLogGroup": {
            "event_type": CloudWatchEventType.LOG_GROUP_CREATED,
            "message": "CloudWatch log group created",
            "formatter": EventMessageFormatter.format_cloudwatch_log_group_created,
        },
        "DeleteLogGroup": {
            "event_type": CloudWatchEventType.LOG_GROUP_DELETED,
            "message": "CloudWatch log group deleted",
            "formatter": EventMessageFormatter.format_cloudwatch_log_group_deleted,
        },
        "PutRetentionPolicy": {
            "event_type": CloudWatchEventType.LOG_RETENTION_CHANGED,
            "message": "CloudWatch log retention changed",
            "formatter": EventMessageFormatter.format_cloudwatch_log_retention_changed,
        },
    }

    # Event mappings for SNS
    SNS_EVENTS = {
        "CreateTopic": {
            "event_type": SNSEventType.TOPIC_CREATED,
            "message": "SNS topic created",
            "formatter": EventMessageFormatter.format_sns_topic_created,
        },
        "DeleteTopic": {
            "event_type": SNSEventType.TOPIC_DELETED,
            "message": "SNS topic deleted",
            "formatter": EventMessageFormatter.format_sns_topic_deleted,
        },
        "SetTopicAttributes": {
            "event_type": SNSEventType.TOPIC_ATTRIBUTE_CHANGED,
            "message": "SNS topic attributes changed",
            "formatter": EventMessageFormatter.format_sns_topic_attribute_changed,
        },
        "Subscribe": {
            "event_type": SNSEventType.SUBSCRIPTION_CREATED,
            "message": "SNS subscription created",
            "formatter": EventMessageFormatter.format_sns_subscription_created,
        },
        "Unsubscribe": {
            "event_type": SNSEventType.SUBSCRIPTION_DELETED,
            "message": "SNS subscription deleted",
            "formatter": EventMessageFormatter.format_sns_subscription_deleted,
        },
    }

    # Event mappings for SQS
    SQS_EVENTS = {
        "CreateQueue": {
            "event_type": SQSEventType.QUEUE_CREATED,
            "message": "SQS queue created",
            "formatter": EventMessageFormatter.format_sqs_queue_created,
        },
        "DeleteQueue": {
            "event_type": SQSEventType.QUEUE_DELETED,
            "message": "SQS queue deleted",
            "formatter": EventMessageFormatter.format_sqs_queue_deleted,
        },
        "SetQueueAttributes": {
            "event_type": SQSEventType.QUEUE_ATTRIBUTE_CHANGED,
            "message": "SQS queue attributes changed",
            "formatter": EventMessageFormatter.format_sqs_queue_attribute_changed,
        },
        "AddPermission": {
            "event_type": SQSEventType.QUEUE_POLICY_CHANGED,
            "message": "SQS queue policy changed",
            "formatter": EventMessageFormatter.format_sqs_queue_policy_changed,
        },
        "RemovePermission": {
            "event_type": SQSEventType.QUEUE_POLICY_CHANGED,
            "message": "SQS queue policy changed",
            "formatter": EventMessageFormatter.format_sqs_queue_policy_changed,
        },
    }

    # Event mappings for ECR
    ECR_EVENTS = {
        "CreateRepository": {
            "event_type": ECREventType.REPOSITORY_CREATED,
            "message": "ECR repository created",
            "formatter": EventMessageFormatter.format_ecr_repository_created,
        },
        "DeleteRepository": {
            "event_type": ECREventType.REPOSITORY_DELETED,
            "message": "ECR repository deleted",
            "formatter": EventMessageFormatter.format_ecr_repository_deleted,
        },
        "PutImage": {
            "event_type": ECREventType.IMAGE_PUSHED,
            "message": "ECR image pushed",
            "formatter": EventMessageFormatter.format_ecr_image_pushed,
        },
        "BatchDeleteImage": {
            "event_type": ECREventType.IMAGE_DELETED,
            "message": "ECR image(s) deleted",
            "formatter": EventMessageFormatter.format_ecr_image_deleted,
        },
        "PutLifecyclePolicy": {
            "event_type": ECREventType.LIFECYCLE_POLICY_SET,
            "message": "ECR lifecycle policy set",
            "formatter": EventMessageFormatter.format_ecr_lifecycle_policy_set,
        },
        "SetRepositoryPolicy": {
            "event_type": ECREventType.REPOSITORY_POLICY_SET,
            "message": "ECR repository policy set",
            "formatter": EventMessageFormatter.format_ecr_repository_policy_set,
        },
        "PutImageScanningConfiguration": {
            "event_type": ECREventType.IMAGE_SCAN_CONFIGURED,
            "message": "ECR image scanning configured",
            "formatter": EventMessageFormatter.format_ecr_image_scan_configured,
        },
    }

    # Event mappings for ECS
    ECS_EVENTS = {
        "CreateCluster": {
            "event_type": ECSEventType.CLUSTER_CREATED,
            "message": "ECS cluster created",
            "formatter": EventMessageFormatter.format_ecs_cluster_created,
        },
        "DeleteCluster": {
            "event_type": ECSEventType.CLUSTER_DELETED,
            "message": "ECS cluster deleted",
            "formatter": EventMessageFormatter.format_ecs_cluster_deleted,
        },
        "CreateService": {
            "event_type": ECSEventType.SERVICE_CREATED,
            "message": "ECS service created",
            "formatter": EventMessageFormatter.format_ecs_service_created,
        },
        "DeleteService": {
            "event_type": ECSEventType.SERVICE_DELETED,
            "message": "ECS service deleted",
            "formatter": EventMessageFormatter.format_ecs_service_deleted,
        },
        "UpdateService": {
            "event_type": ECSEventType.SERVICE_UPDATED,
            "message": "ECS service updated",
            "formatter": EventMessageFormatter.format_ecs_service_updated,
        },
        "RegisterTaskDefinition": {
            "event_type": ECSEventType.TASK_DEFINITION_REGISTERED,
            "message": "ECS task definition registered",
            "formatter": EventMessageFormatter.format_ecs_task_definition_registered,
        },
        "DeregisterTaskDefinition": {
            "event_type": ECSEventType.TASK_DEFINITION_DEREGISTERED,
            "message": "ECS task definition deregistered",
            "formatter": EventMessageFormatter.format_ecs_task_definition_deregistered,
        },
    }

    def __init__(
        self,
        session,
        lookback_days: int = 90,
    ):
        """Initialize CloudTrail enricher.

        Args:
            session: AWS session object to create CloudTrail clients
            lookback_days: Days to look back for events (default: 90, max: 90)
        """
        self.session = session
        self.lookback_days = lookback_days

        # Calculate time range based on lookback days
        self.end_time = datetime.now(timezone.utc)
        self.start_time = self.end_time - timedelta(days=self.lookback_days)

    def enrich_finding(
        self, resource_id: str, resource_arn: str, region: str
    ) -> list[dict]:
        """Get CloudTrail timeline events for a resource.

        Args:
            resource_id: AWS resource ID (e.g., sg-1234567890abcdef0)
            resource_arn: AWS resource ARN
            region: AWS region

        Returns:
            List of timeline event dictionaries, empty list if no events found
        """
        try:
            if not resource_id:
                logger.info(
                    "CloudTrail - Skipping enrichment for resource without resource_id"
                )
                return []

            if not region:
                logger.info("CloudTrail - Skipping enrichment - missing region")
                return []

            # Determine resource type from ARN
            resource_type = self._determine_resource_type_from_arn(resource_arn)

            # Query CloudTrail
            timeline_events = self._lookup_resource_events(
                resource_id, resource_type, region
            )
            if not timeline_events:
                logger.info(
                    "CloudTrail - No events found for resource %s with type %s",
                    resource_arn,
                    resource_type,
                )
                return []

            logger.info(
                "CloudTrail - Found %d timeline events for resource %s",
                len(timeline_events),
                resource_arn,
            )

            # Convert timeline events to dictionaries with JSON-serializable values
            return [
                {
                    **event.dict(),
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type.value,
                }
                for event in timeline_events
            ]

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDeniedException":
                logger.warning(
                    "CloudTrail - Missing permissions to enrich findings. "
                    "Add 'cloudtrail:LookupEvents' permission to continue."
                )
            else:
                logger.error(
                    f"{region} -- {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                )
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return []

    def _lookup_resource_events(
        self, resource_id: str, resource_type: str, region: str
    ) -> list[TimelineEvent]:
        """Query CloudTrail for events related to a specific resource.

        Args:
            resource_id: AWS resource ID (e.g., i-1234567890abcdef0)
            resource_type: Resource type (e.g., "AWS::EC2::Instance")
            region: AWS region to query

        Returns:
            List of timeline events
        """
        # Get supported events for this resource type
        supported_events = self._get_supported_events(resource_type)
        if not supported_events:
            logger.info(
                "CloudTrail - No supported events for resource type: %s", resource_type
            )
            return []

        timeline_events = []

        try:
            # Create CloudTrail client for the specific region using the session
            regional_client = self.session.client("cloudtrail", region_name=region)

            # Build lookup parameters
            params = {
                "LookupAttributes": [
                    {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
                ]
            }
            if self.start_time:
                params["StartTime"] = self.start_time
            if self.end_time:
                params["EndTime"] = self.end_time

            # Use paginator to get ALL events (no limit)
            paginator = regional_client.get_paginator("lookup_events")
            page_iterator = paginator.paginate(**params)

            for page in page_iterator:
                for event in page.get("Events", []):
                    event_name = event.get("EventName")

                    if event_name in supported_events:
                        timeline_event = self._parse_cloudtrail_event(
                            event, resource_id, resource_type, supported_events
                        )
                        if timeline_event:
                            timeline_events.append(timeline_event)

        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return timeline_events

    def _parse_cloudtrail_event(
        self,
        event: dict[str, Any],
        resource_id: str,
        resource_type: str,
        supported_events: dict,
    ) -> TimelineEvent | None:
        """Parse a CloudTrail event into a TimelineEvent.

        Args:
            event: Raw CloudTrail event from API
            resource_id: Resource ID being enriched
            resource_type: AWS resource type
            supported_events: Mapping of supported event names to metadata

        Returns:
            TimelineEvent or None if parsing fails
        """
        try:
            event_name = event.get("EventName")
            event_metadata = supported_events.get(event_name, {})

            # Parse CloudTrail event JSON
            event_details = event.get("CloudTrailEvent", "")
            if isinstance(event_details, str):
                event_details = json.loads(event_details)

            # Extract principal (who performed the action)
            principal = EventMessageFormatter.extract_principal_name(event_details)

            # Build message
            base_message = event_metadata.get("message", event_name)
            if formatter := event_metadata.get("formatter"):
                formatted_message = formatter(event_details)
                message = f"{base_message} by {principal}. {formatted_message}"
            else:
                message = f"{base_message} by {principal}"

            return TimelineEvent(
                timestamp=event["EventTime"],
                event_source="AWS CloudTrail",
                event_type=event_metadata.get(
                    "event_type", GeneralEventType.RESOURCE_MODIFIED
                ),
                resource_type=resource_type,
                resource_id=resource_id,
                principal=principal,
                message=message,
                event_details=event_details,
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _get_supported_events(self, resource_type: str) -> dict:
        """Get supported CloudTrail events for a resource type.

        Args:
            resource_type: AWS resource type

        Returns:
            Dictionary mapping event names to event metadata
        """
        if (
            "Instance" in resource_type
            and "RDS" not in resource_type
            and "DBInstance" not in resource_type
        ):
            return self.EC2_INSTANCE_EVENTS
        elif "SecurityGroup" in resource_type:
            return self.SECURITY_GROUP_EVENTS
        elif "NetworkInterface" in resource_type:
            return self.NETWORK_INTERFACE_EVENTS
        elif "LoadBalancer" in resource_type and "ELBV2" not in resource_type:
            return self.LOAD_BALANCER_EVENTS
        elif (
            "RDS" in resource_type
            or "DBInstance" in resource_type
            or "DBCluster" in resource_type
        ):
            return self.RDS_INSTANCE_EVENTS
        elif "S3" in resource_type or "Bucket" in resource_type:
            return self.S3_BUCKET_EVENTS
        elif "Lambda" in resource_type or "Function" in resource_type:
            return self.LAMBDA_FUNCTION_EVENTS
        elif (
            "VPC" in resource_type
            or "Subnet" in resource_type
            or "RouteTable" in resource_type
            or "InternetGateway" in resource_type
            or "NatGateway" in resource_type
        ):
            return self.VPC_EVENTS
        elif (
            "ELBV2" in resource_type
            or "TargetGroup" in resource_type
            or "Listener" in resource_type
        ):
            return self.ELBV2_EVENTS
        elif (
            "IAM" in resource_type
            or "User" in resource_type
            or "Role" in resource_type
            or "Policy" in resource_type
        ):
            return self.IAM_EVENTS
        elif "DynamoDB" in resource_type or "Table" in resource_type:
            return self.DYNAMODB_EVENTS
        elif "KMS" in resource_type or "Key" in resource_type:
            return self.KMS_EVENTS
        elif "CloudTrail" in resource_type or "Trail" in resource_type:
            return self.CLOUDTRAIL_EVENTS
        elif "Volume" in resource_type or "Snapshot" in resource_type:
            return self.EBS_EVENTS
        elif "SecretsManager" in resource_type or "Secret" in resource_type:
            return self.SECRETS_MANAGER_EVENTS
        elif (
            "CloudWatch" in resource_type
            or "Alarm" in resource_type
            or "LogGroup" in resource_type
        ):
            return self.CLOUDWATCH_EVENTS
        elif "SNS" in resource_type or "Topic" in resource_type:
            return self.SNS_EVENTS
        elif "SQS" in resource_type or "Queue" in resource_type:
            return self.SQS_EVENTS
        elif "ECR" in resource_type or "Repository" in resource_type:
            return self.ECR_EVENTS
        elif (
            "ECS" in resource_type
            or "Cluster" in resource_type
            or "Service" in resource_type
            or "TaskDefinition" in resource_type
        ):
            return self.ECS_EVENTS
        else:
            logger.info(
                "CloudTrail - Unsupported resource type for enrichment: %s",
                resource_type,
            )
            return {}

    def _determine_resource_type_from_arn(self, resource_arn: str) -> str:
        """Determine AWS resource type from ARN.

        Args:
            resource_arn: Resource ARN

        Returns:
            AWS resource type string (e.g., "AWS::EC2::Instance")
        """
        if not resource_arn:
            return "AWS::Unknown"

        # Parse resource type from ARN
        # Format: arn:aws:service:region:account:resource-type/resource-id
        parts = resource_arn.split(":")
        if len(parts) >= 6:
            service = parts[2]
            resource_part = parts[5]

            if "/" in resource_part:
                resource_type_part = resource_part.split("/")[0]
            else:
                resource_type_part = resource_part

            # Map service to AWS resource type
            if service == "ec2" or service == "vpc":
                if resource_type_part.startswith("instance"):
                    return "AWS::EC2::Instance"
                elif resource_type_part.startswith("security-group"):
                    return "AWS::EC2::SecurityGroup"
                elif resource_type_part.startswith("network-interface"):
                    return "AWS::EC2::NetworkInterface"
                elif "image" in resource_type_part:
                    return "AWS::EC2::Image"
                elif "network-acl" in resource_type_part:
                    return "AWS::EC2::NetworkACL"
                elif "vpc" in resource_type_part:
                    return "AWS::EC2::VPC"
                elif "subnet" in resource_type_part:
                    return "AWS::EC2::Subnet"
                elif "route-table" in resource_type_part:
                    return "AWS::EC2::RouteTable"
                elif "internet-gateway" in resource_type_part:
                    return "AWS::EC2::InternetGateway"
                elif "nat-gateway" in resource_type_part:
                    return "AWS::EC2::NatGateway"
                elif "volume" in resource_type_part:
                    return "AWS::EC2::Volume"
                elif "snapshot" in resource_type_part:
                    return "AWS::EC2::Snapshot"
                elif "eip-allocation" in resource_type_part:
                    return "AWS::EC2::EIPAllocation"
                elif "eip-association" in resource_type_part:
                    return "AWS::EC2::EIPAssociation"
                elif "eip" in resource_type_part:
                    return "AWS::EC2::EIP"
            elif service == "elasticloadbalancing":
                if (
                    "loadbalancer/app" in resource_part
                    or "loadbalancer/net" in resource_part
                ):
                    return "AWS::ElasticLoadBalancingV2::LoadBalancer"
                elif "targetgroup" in resource_part:
                    return "AWS::ElasticLoadBalancingV2::TargetGroup"
                else:
                    return "AWS::ElasticLoadBalancing::LoadBalancer"
            elif service == "rds":
                if resource_type_part.startswith("db"):
                    if "cluster" in resource_type_part:
                        return "AWS::RDS::DBCluster"
                    elif "snapshot" in resource_type_part:
                        return "AWS::RDS::DBSnapshot"
                    else:
                        return "AWS::RDS::DBInstance"
            elif service == "s3":
                return "AWS::S3::Bucket"
            elif service == "lambda":
                if resource_type_part.startswith("function"):
                    return "AWS::Lambda::Function"
            elif service == "iam":
                if "user/" in resource_part:
                    return "AWS::IAM::User"
                elif "role/" in resource_part:
                    return "AWS::IAM::Role"
                elif "policy/" in resource_part:
                    return "AWS::IAM::Policy"
                else:
                    return "AWS::IAM::Resource"
            elif service == "dynamodb":
                if resource_type_part.startswith("table"):
                    return "AWS::DynamoDB::Table"
            elif service == "kms":
                if resource_type_part.startswith("key"):
                    return "AWS::KMS::Key"
            elif service == "cloudtrail":
                if resource_type_part.startswith("trail"):
                    return "AWS::CloudTrail::Trail"
            elif service == "secretsmanager":
                if resource_type_part.startswith("secret"):
                    return "AWS::SecretsManager::Secret"
            elif service == "cloudwatch":
                if "alarm" in resource_type_part:
                    return "AWS::CloudWatch::Alarm"
            elif service == "logs":
                if "log-group" in resource_type_part:
                    return "AWS::Logs::LogGroup"
            elif service == "sns":
                if resource_type_part.startswith("topic") or "/" not in resource_part:
                    return "AWS::SNS::Topic"
                elif "subscription" in resource_type_part:
                    return "AWS::SNS::Subscription"
            elif service == "sqs":
                return "AWS::SQS::Queue"
            elif service == "ecr":
                if resource_type_part.startswith("repository"):
                    return "AWS::ECR::Repository"
            elif service == "ecs":
                if "cluster" in resource_type_part:
                    return "AWS::ECS::Cluster"
                elif "service" in resource_type_part:
                    return "AWS::ECS::Service"
                elif "task-definition" in resource_type_part:
                    return "AWS::ECS::TaskDefinition"

        return "AWS::Unknown"
