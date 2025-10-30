"""CloudTrail enrichment service for Prowler findings.

This module queries AWS CloudTrail to enrich security findings with timeline
context showing who performed actions, what changed, and when events occurred.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from prowler.lib.logger import logger
from prowler.providers.aws.services.cloudtrail.lib.enrichment.formatters import (
    EventMessageFormatter,
)
from prowler.providers.aws.services.cloudtrail.lib.enrichment.models import (
    FindingEnrichment,
    TimelineEvent,
    TimelineEventType,
)


class CloudTrailEnricher:
    """Enriches findings with CloudTrail event timeline.

    Queries CloudTrail to build a timeline of events for resources in findings,
    providing context about who created/modified resources and when.
    """

    # Event mappings for EC2 Instances
    EC2_INSTANCE_EVENTS = {
        "RunInstances": {
            "event_type": TimelineEventType.INSTANCE_CREATED,
            "message": "Instance created",
            "formatter": EventMessageFormatter.format_instance_created,
        },
        "TerminateInstances": {
            "event_type": TimelineEventType.INSTANCE_TERMINATED,
            "message": "Instance terminated",
        },
        "StartInstances": {
            "event_type": TimelineEventType.INSTANCE_STARTED,
            "message": "Instance started",
        },
        "StopInstances": {
            "event_type": TimelineEventType.INSTANCE_STOPPED,
            "message": "Instance stopped",
        },
        "RebootInstances": {
            "event_type": TimelineEventType.INSTANCE_REBOOTED,
            "message": "Instance rebooted",
        },
    }

    # Event mappings for Security Groups
    SECURITY_GROUP_EVENTS = {
        "CreateSecurityGroup": {
            "event_type": TimelineEventType.SECURITY_GROUP_CREATED,
            "message": "Security group created",
        },
        "AuthorizeSecurityGroupIngress": {
            "event_type": TimelineEventType.SECURITY_GROUP_RULE_ADDED,
            "message": "Ingress rule added",
            "formatter": EventMessageFormatter.format_security_group_rule_added,
        },
        "ModifySecurityGroupRules": {
            "event_type": TimelineEventType.SECURITY_GROUP_RULE_MODIFIED,
            "message": "Security group rules modified",
            "formatter": EventMessageFormatter.format_security_group_rule_modified,
        },
        "RevokeSecurityGroupIngress": {
            "event_type": TimelineEventType.SECURITY_GROUP_RULE_REMOVED,
            "message": "Ingress rule removed",
            "formatter": EventMessageFormatter.format_security_group_rule_removed,
        },
    }

    # Event mappings for Network Interfaces
    NETWORK_INTERFACE_EVENTS = {
        "CreateNetworkInterface": {
            "event_type": TimelineEventType.NETWORK_INTERFACE_CREATED,
            "message": "Network interface created",
        },
        "ModifyNetworkInterfaceAttribute": {
            "event_type": TimelineEventType.NETWORK_INTERFACE_MODIFIED,
            "message": "Network interface modified",
            "formatter": EventMessageFormatter.format_eni_attribute_modification,
        },
        "AttachNetworkInterface": {
            "event_type": TimelineEventType.NETWORK_INTERFACE_ATTACHED,
            "message": "Network interface attached",
        },
        "DetachNetworkInterface": {
            "event_type": TimelineEventType.NETWORK_INTERFACE_DETACHED,
            "message": "Network interface detached",
        },
    }

    # Event mappings for Load Balancers
    LOAD_BALANCER_EVENTS = {
        "CreateLoadBalancer": {
            "event_type": TimelineEventType.LOAD_BALANCER_CREATED,
            "message": "Load balancer created",
            "formatter": EventMessageFormatter.format_load_balancer_created,
        },
        "ModifyLoadBalancerAttributes": {
            "event_type": TimelineEventType.LOAD_BALANCER_MODIFIED,
            "message": "Load balancer attributes modified",
        },
        "DeleteLoadBalancer": {
            "event_type": TimelineEventType.LOAD_BALANCER_DELETED,
            "message": "Load balancer deleted",
        },
    }

    # Event mappings for RDS Instances
    RDS_INSTANCE_EVENTS = {
        "CreateDBInstance": {
            "event_type": TimelineEventType.RDS_INSTANCE_CREATED,
            "message": "RDS instance created",
            "formatter": EventMessageFormatter.format_rds_instance_created,
        },
        "ModifyDBInstance": {
            "event_type": TimelineEventType.RDS_INSTANCE_MODIFIED,
            "message": "RDS instance modified",
            "formatter": EventMessageFormatter.format_rds_instance_modified,
        },
        "DeleteDBInstance": {
            "event_type": TimelineEventType.RDS_INSTANCE_DELETED,
            "message": "RDS instance deleted",
        },
        "CreateDBSnapshot": {
            "event_type": TimelineEventType.RDS_SNAPSHOT_CREATED,
            "message": "RDS snapshot created",
        },
        "ModifyDBSnapshotAttribute": {
            "event_type": TimelineEventType.RDS_SNAPSHOT_SHARED,
            "message": "RDS snapshot sharing modified",
            "formatter": EventMessageFormatter.format_rds_snapshot_shared,
        },
        "CreateDBCluster": {
            "event_type": TimelineEventType.RDS_CLUSTER_CREATED,
            "message": "RDS cluster created",
        },
        "ModifyDBCluster": {
            "event_type": TimelineEventType.RDS_CLUSTER_MODIFIED,
            "message": "RDS cluster modified",
        },
    }

    # Event mappings for S3 Buckets
    S3_BUCKET_EVENTS = {
        "CreateBucket": {
            "event_type": TimelineEventType.S3_BUCKET_CREATED,
            "message": "S3 bucket created",
            "formatter": EventMessageFormatter.format_s3_bucket_created,
        },
        "DeleteBucket": {
            "event_type": TimelineEventType.S3_BUCKET_DELETED,
            "message": "S3 bucket deleted",
        },
        "PutBucketPolicy": {
            "event_type": TimelineEventType.S3_BUCKET_POLICY_CHANGED,
            "message": "S3 bucket policy changed",
            "formatter": EventMessageFormatter.format_s3_bucket_policy_changed,
        },
        "DeleteBucketPolicy": {
            "event_type": TimelineEventType.S3_BUCKET_POLICY_CHANGED,
            "message": "S3 bucket policy deleted",
        },
        "PutPublicAccessBlock": {
            "event_type": TimelineEventType.S3_PUBLIC_ACCESS_BLOCK_CHANGED,
            "message": "S3 public access block configuration changed",
            "formatter": EventMessageFormatter.format_s3_public_access_block_changed,
        },
        "DeletePublicAccessBlock": {
            "event_type": TimelineEventType.S3_PUBLIC_ACCESS_BLOCK_CHANGED,
            "message": "S3 public access block removed",
        },
        "PutBucketEncryption": {
            "event_type": TimelineEventType.S3_ENCRYPTION_CHANGED,
            "message": "S3 bucket encryption configured",
            "formatter": EventMessageFormatter.format_s3_encryption_changed,
        },
        "DeleteBucketEncryption": {
            "event_type": TimelineEventType.S3_ENCRYPTION_CHANGED,
            "message": "S3 bucket encryption removed",
        },
        "PutBucketVersioning": {
            "event_type": TimelineEventType.S3_VERSIONING_CHANGED,
            "message": "S3 bucket versioning changed",
        },
        "PutBucketLogging": {
            "event_type": TimelineEventType.S3_LOGGING_CHANGED,
            "message": "S3 bucket logging configured",
        },
    }

    # Event mappings for Lambda Functions
    LAMBDA_FUNCTION_EVENTS = {
        "CreateFunction": {
            "event_type": TimelineEventType.LAMBDA_FUNCTION_CREATED,
            "message": "Lambda function created",
            "formatter": EventMessageFormatter.format_lambda_function_created,
        },
        "DeleteFunction": {
            "event_type": TimelineEventType.LAMBDA_FUNCTION_DELETED,
            "message": "Lambda function deleted",
        },
        "UpdateFunctionConfiguration": {
            "event_type": TimelineEventType.LAMBDA_FUNCTION_UPDATED,
            "message": "Lambda function configuration updated",
        },
        "UpdateFunctionCode": {
            "event_type": TimelineEventType.LAMBDA_CODE_UPDATED,
            "message": "Lambda function code updated",
            "formatter": EventMessageFormatter.format_lambda_code_updated,
        },
        "AddPermission": {
            "event_type": TimelineEventType.LAMBDA_PERMISSION_ADDED,
            "message": "Lambda permission added",
            "formatter": EventMessageFormatter.format_lambda_permission_added,
        },
        "CreateFunctionUrlConfig": {
            "event_type": TimelineEventType.LAMBDA_FUNCTION_URL_CREATED,
            "message": "Lambda function URL created",
            "formatter": EventMessageFormatter.format_lambda_function_url_created,
        },
        "UpdateFunctionUrlConfig": {
            "event_type": TimelineEventType.LAMBDA_FUNCTION_URL_CREATED,
            "message": "Lambda function URL updated",
        },
    }

    # Event mappings for VPC Resources
    VPC_EVENTS = {
        "CreateVpc": {
            "event_type": TimelineEventType.VPC_CREATED,
            "message": "VPC created",
        },
        "CreateSubnet": {
            "event_type": TimelineEventType.SUBNET_CREATED,
            "message": "Subnet created",
            "formatter": EventMessageFormatter.format_subnet_created,
        },
        "ModifySubnetAttribute": {
            "event_type": TimelineEventType.SUBNET_MODIFIED,
            "message": "Subnet modified",
            "formatter": EventMessageFormatter.format_subnet_modified,
        },
        "CreateRouteTable": {
            "event_type": TimelineEventType.ROUTE_TABLE_CREATED,
            "message": "Route table created",
        },
        "CreateRoute": {
            "event_type": TimelineEventType.ROUTE_CREATED,
            "message": "Route created",
            "formatter": EventMessageFormatter.format_route_created,
        },
        "CreateInternetGateway": {
            "event_type": TimelineEventType.INTERNET_GATEWAY_CREATED,
            "message": "Internet gateway created",
        },
        "AttachInternetGateway": {
            "event_type": TimelineEventType.INTERNET_GATEWAY_ATTACHED,
            "message": "Internet gateway attached",
            "formatter": EventMessageFormatter.format_internet_gateway_attached,
        },
        "CreateNatGateway": {
            "event_type": TimelineEventType.NAT_GATEWAY_CREATED,
            "message": "NAT gateway created",
        },
        "CreateVpcEndpoint": {
            "event_type": TimelineEventType.VPC_ENDPOINT_CREATED,
            "message": "VPC endpoint created",
            "formatter": EventMessageFormatter.format_vpc_endpoint_created,
        },
        "CreateNetworkAcl": {
            "event_type": TimelineEventType.NETWORK_ACL_CREATED,
            "message": "Network ACL created",
        },
        "CreateNetworkAclEntry": {
            "event_type": TimelineEventType.NETWORK_ACL_ENTRY_CREATED,
            "message": "Network ACL entry created",
        },
    }

    # Event mappings for ELBv2 (ALB/NLB)
    ELBV2_EVENTS = {
        "CreateLoadBalancer": {
            "event_type": TimelineEventType.ELBV2_LOAD_BALANCER_CREATED,
            "message": "Load balancer created",
            "formatter": EventMessageFormatter.format_elbv2_load_balancer_created,
        },
        "ModifyLoadBalancerAttributes": {
            "event_type": TimelineEventType.ELBV2_LOAD_BALANCER_MODIFIED,
            "message": "Load balancer attributes modified",
        },
        "DeleteLoadBalancer": {
            "event_type": TimelineEventType.ELBV2_LOAD_BALANCER_DELETED,
            "message": "Load balancer deleted",
        },
        "CreateListener": {
            "event_type": TimelineEventType.ELBV2_LISTENER_CREATED,
            "message": "Listener created",
            "formatter": EventMessageFormatter.format_elbv2_listener_created,
        },
        "ModifyListener": {
            "event_type": TimelineEventType.ELBV2_LISTENER_MODIFIED,
            "message": "Listener modified",
        },
        "CreateTargetGroup": {
            "event_type": TimelineEventType.ELBV2_TARGET_GROUP_CREATED,
            "message": "Target group created",
        },
    }

    # Event mappings for IAM
    IAM_EVENTS = {
        "CreateUser": {
            "event_type": TimelineEventType.IAM_USER_CREATED,
            "message": "IAM user created",
            "formatter": EventMessageFormatter.format_iam_user_created,
        },
        "DeleteUser": {
            "event_type": TimelineEventType.IAM_USER_DELETED,
            "message": "IAM user deleted",
        },
        "CreateRole": {
            "event_type": TimelineEventType.IAM_ROLE_CREATED,
            "message": "IAM role created",
            "formatter": EventMessageFormatter.format_iam_role_created,
        },
        "DeleteRole": {
            "event_type": TimelineEventType.IAM_ROLE_DELETED,
            "message": "IAM role deleted",
        },
        "AttachUserPolicy": {
            "event_type": TimelineEventType.IAM_POLICY_ATTACHED,
            "message": "Policy attached to user",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "AttachRolePolicy": {
            "event_type": TimelineEventType.IAM_POLICY_ATTACHED,
            "message": "Policy attached to role",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "AttachGroupPolicy": {
            "event_type": TimelineEventType.IAM_POLICY_ATTACHED,
            "message": "Policy attached to group",
            "formatter": EventMessageFormatter.format_iam_policy_attached,
        },
        "CreatePolicy": {
            "event_type": TimelineEventType.IAM_POLICY_CREATED,
            "message": "IAM policy created",
        },
        "CreateAccessKey": {
            "event_type": TimelineEventType.IAM_ACCESS_KEY_CREATED,
            "message": "Access key created",
            "formatter": EventMessageFormatter.format_iam_access_key_created,
        },
        "AddUserToGroup": {
            "event_type": TimelineEventType.IAM_USER_ADDED_TO_GROUP,
            "message": "User added to group",
        },
        "UpdateAssumeRolePolicy": {
            "event_type": TimelineEventType.IAM_ASSUME_ROLE_POLICY_UPDATED,
            "message": "Assume role policy updated",
        },
    }

    # Event mappings for DynamoDB
    DYNAMODB_EVENTS = {
        "CreateTable": {
            "event_type": TimelineEventType.DYNAMODB_TABLE_CREATED,
            "message": "DynamoDB table created",
            "formatter": EventMessageFormatter.format_dynamodb_table_created,
        },
        "UpdateTable": {
            "event_type": TimelineEventType.DYNAMODB_TABLE_UPDATED,
            "message": "DynamoDB table updated",
        },
        "DeleteTable": {
            "event_type": TimelineEventType.DYNAMODB_TABLE_DELETED,
            "message": "DynamoDB table deleted",
        },
        "CreateBackup": {
            "event_type": TimelineEventType.DYNAMODB_BACKUP_CREATED,
            "message": "DynamoDB backup created",
        },
        "UpdateContinuousBackups": {
            "event_type": TimelineEventType.DYNAMODB_PITR_UPDATED,
            "message": "DynamoDB PITR configuration updated",
            "formatter": EventMessageFormatter.format_dynamodb_pitr_updated,
        },
    }

    # Event mappings for KMS
    KMS_EVENTS = {
        "CreateKey": {
            "event_type": TimelineEventType.KMS_KEY_CREATED,
            "message": "KMS key created",
            "formatter": EventMessageFormatter.format_kms_key_created,
        },
        "ScheduleKeyDeletion": {
            "event_type": TimelineEventType.KMS_KEY_DELETION_SCHEDULED,
            "message": "KMS key deletion scheduled",
            "formatter": EventMessageFormatter.format_kms_key_deletion_scheduled,
        },
        "CancelKeyDeletion": {
            "event_type": TimelineEventType.KMS_KEY_DELETION_CANCELLED,
            "message": "KMS key deletion cancelled",
            "formatter": EventMessageFormatter.format_kms_key_deletion_cancelled,
        },
        "DisableKey": {
            "event_type": TimelineEventType.KMS_KEY_DISABLED,
            "message": "KMS key disabled",
            "formatter": EventMessageFormatter.format_kms_key_disabled,
        },
        "EnableKey": {
            "event_type": TimelineEventType.KMS_KEY_ENABLED,
            "message": "KMS key enabled",
            "formatter": EventMessageFormatter.format_kms_key_enabled,
        },
        "EnableKeyRotation": {
            "event_type": TimelineEventType.KMS_KEY_ROTATION_ENABLED,
            "message": "KMS key rotation enabled",
            "formatter": EventMessageFormatter.format_kms_key_rotation_enabled,
        },
        "DisableKeyRotation": {
            "event_type": TimelineEventType.KMS_KEY_ROTATION_DISABLED,
            "message": "KMS key rotation disabled",
            "formatter": EventMessageFormatter.format_kms_key_rotation_disabled,
        },
        "PutKeyPolicy": {
            "event_type": TimelineEventType.KMS_KEY_POLICY_CHANGED,
            "message": "KMS key policy changed",
            "formatter": EventMessageFormatter.format_kms_key_policy_changed,
        },
        "ImportKeyMaterial": {
            "event_type": TimelineEventType.KMS_KEY_IMPORTED,
            "message": "KMS key material imported",
            "formatter": EventMessageFormatter.format_kms_key_imported,
        },
        "CreateGrant": {
            "event_type": TimelineEventType.KMS_GRANT_CREATED,
            "message": "KMS grant created",
            "formatter": EventMessageFormatter.format_kms_grant_created,
        },
        "RevokeGrant": {
            "event_type": TimelineEventType.KMS_GRANT_REVOKED,
            "message": "KMS grant revoked",
            "formatter": EventMessageFormatter.format_kms_grant_revoked,
        },
    }

    # Event mappings for CloudTrail
    CLOUDTRAIL_EVENTS = {
        "CreateTrail": {
            "event_type": TimelineEventType.CLOUDTRAIL_TRAIL_CREATED,
            "message": "CloudTrail trail created",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_created,
        },
        "DeleteTrail": {
            "event_type": TimelineEventType.CLOUDTRAIL_TRAIL_DELETED,
            "message": "CloudTrail trail deleted",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_deleted,
        },
        "UpdateTrail": {
            "event_type": TimelineEventType.CLOUDTRAIL_TRAIL_UPDATED,
            "message": "CloudTrail trail updated",
            "formatter": EventMessageFormatter.format_cloudtrail_trail_updated,
        },
        "StopLogging": {
            "event_type": TimelineEventType.CLOUDTRAIL_LOGGING_STOPPED,
            "message": "CloudTrail logging stopped",
            "formatter": EventMessageFormatter.format_cloudtrail_logging_stopped,
        },
        "StartLogging": {
            "event_type": TimelineEventType.CLOUDTRAIL_LOGGING_STARTED,
            "message": "CloudTrail logging started",
            "formatter": EventMessageFormatter.format_cloudtrail_logging_started,
        },
        "PutEventSelectors": {
            "event_type": TimelineEventType.CLOUDTRAIL_EVENT_SELECTORS_UPDATED,
            "message": "CloudTrail event selectors updated",
            "formatter": EventMessageFormatter.format_cloudtrail_event_selectors_updated,
        },
    }

    # Event mappings for EBS
    EBS_EVENTS = {
        "CreateVolume": {
            "event_type": TimelineEventType.EBS_VOLUME_CREATED,
            "message": "EBS volume created",
            "formatter": EventMessageFormatter.format_ebs_volume_created,
        },
        "DeleteVolume": {
            "event_type": TimelineEventType.EBS_VOLUME_DELETED,
            "message": "EBS volume deleted",
            "formatter": EventMessageFormatter.format_ebs_volume_deleted,
        },
        "ModifyVolume": {
            "event_type": TimelineEventType.EBS_VOLUME_MODIFIED,
            "message": "EBS volume modified",
            "formatter": EventMessageFormatter.format_ebs_volume_modified,
        },
        "CreateSnapshot": {
            "event_type": TimelineEventType.EBS_SNAPSHOT_CREATED,
            "message": "EBS snapshot created",
            "formatter": EventMessageFormatter.format_ebs_snapshot_created,
        },
        "DeleteSnapshot": {
            "event_type": TimelineEventType.EBS_SNAPSHOT_DELETED,
            "message": "EBS snapshot deleted",
            "formatter": EventMessageFormatter.format_ebs_snapshot_deleted,
        },
        "ModifySnapshotAttribute": {
            "event_type": TimelineEventType.EBS_SNAPSHOT_SHARED,
            "message": "EBS snapshot permissions modified",
            "formatter": EventMessageFormatter.format_ebs_snapshot_shared,
        },
        "EnableEbsEncryptionByDefault": {
            "event_type": TimelineEventType.EBS_ENCRYPTION_ENABLED,
            "message": "EBS encryption by default enabled",
            "formatter": EventMessageFormatter.format_ebs_encryption_enabled,
        },
        "DisableEbsEncryptionByDefault": {
            "event_type": TimelineEventType.EBS_ENCRYPTION_DISABLED,
            "message": "EBS encryption by default disabled",
            "formatter": EventMessageFormatter.format_ebs_encryption_disabled,
        },
    }

    # Event mappings for Secrets Manager
    SECRETS_MANAGER_EVENTS = {
        "CreateSecret": {
            "event_type": TimelineEventType.SECRETS_MANAGER_SECRET_CREATED,
            "message": "Secret created",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_created,
        },
        "DeleteSecret": {
            "event_type": TimelineEventType.SECRETS_MANAGER_SECRET_DELETED,
            "message": "Secret deleted",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_deleted,
        },
        "UpdateSecret": {
            "event_type": TimelineEventType.SECRETS_MANAGER_SECRET_UPDATED,
            "message": "Secret updated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_updated,
        },
        "PutSecretValue": {
            "event_type": TimelineEventType.SECRETS_MANAGER_SECRET_UPDATED,
            "message": "Secret value updated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_updated,
        },
        "RotateSecret": {
            "event_type": TimelineEventType.SECRETS_MANAGER_SECRET_ROTATED,
            "message": "Secret rotated",
            "formatter": EventMessageFormatter.format_secrets_manager_secret_rotated,
        },
        "CancelRotateSecret": {
            "event_type": TimelineEventType.SECRETS_MANAGER_ROTATION_DISABLED,
            "message": "Secret rotation disabled",
            "formatter": EventMessageFormatter.format_secrets_manager_rotation_disabled,
        },
        "PutResourcePolicy": {
            "event_type": TimelineEventType.SECRETS_MANAGER_POLICY_CHANGED,
            "message": "Secret resource policy changed",
            "formatter": EventMessageFormatter.format_secrets_manager_policy_changed,
        },
    }

    # Event mappings for CloudWatch
    CLOUDWATCH_EVENTS = {
        "PutMetricAlarm": {
            "event_type": TimelineEventType.CLOUDWATCH_ALARM_CREATED,
            "message": "CloudWatch alarm created/updated",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_created,
        },
        "DeleteAlarms": {
            "event_type": TimelineEventType.CLOUDWATCH_ALARM_DELETED,
            "message": "CloudWatch alarm(s) deleted",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_deleted,
        },
        "SetAlarmState": {
            "event_type": TimelineEventType.CLOUDWATCH_ALARM_STATE_CHANGED,
            "message": "CloudWatch alarm state changed",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_state_changed,
        },
        "DisableAlarmActions": {
            "event_type": TimelineEventType.CLOUDWATCH_ALARM_ACTIONS_DISABLED,
            "message": "CloudWatch alarm actions disabled",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_actions_disabled,
        },
        "EnableAlarmActions": {
            "event_type": TimelineEventType.CLOUDWATCH_ALARM_ACTIONS_ENABLED,
            "message": "CloudWatch alarm actions enabled",
            "formatter": EventMessageFormatter.format_cloudwatch_alarm_actions_enabled,
        },
        "CreateLogGroup": {
            "event_type": TimelineEventType.CLOUDWATCH_LOG_GROUP_CREATED,
            "message": "CloudWatch log group created",
            "formatter": EventMessageFormatter.format_cloudwatch_log_group_created,
        },
        "DeleteLogGroup": {
            "event_type": TimelineEventType.CLOUDWATCH_LOG_GROUP_DELETED,
            "message": "CloudWatch log group deleted",
            "formatter": EventMessageFormatter.format_cloudwatch_log_group_deleted,
        },
        "PutRetentionPolicy": {
            "event_type": TimelineEventType.CLOUDWATCH_LOG_RETENTION_CHANGED,
            "message": "CloudWatch log retention changed",
            "formatter": EventMessageFormatter.format_cloudwatch_log_retention_changed,
        },
    }

    # Event mappings for SNS
    SNS_EVENTS = {
        "CreateTopic": {
            "event_type": TimelineEventType.SNS_TOPIC_CREATED,
            "message": "SNS topic created",
            "formatter": EventMessageFormatter.format_sns_topic_created,
        },
        "DeleteTopic": {
            "event_type": TimelineEventType.SNS_TOPIC_DELETED,
            "message": "SNS topic deleted",
            "formatter": EventMessageFormatter.format_sns_topic_deleted,
        },
        "SetTopicAttributes": {
            "event_type": TimelineEventType.SNS_TOPIC_ATTRIBUTE_CHANGED,
            "message": "SNS topic attributes changed",
            "formatter": EventMessageFormatter.format_sns_topic_attribute_changed,
        },
        "Subscribe": {
            "event_type": TimelineEventType.SNS_SUBSCRIPTION_CREATED,
            "message": "SNS subscription created",
            "formatter": EventMessageFormatter.format_sns_subscription_created,
        },
        "Unsubscribe": {
            "event_type": TimelineEventType.SNS_SUBSCRIPTION_DELETED,
            "message": "SNS subscription deleted",
            "formatter": EventMessageFormatter.format_sns_subscription_deleted,
        },
    }

    # Event mappings for SQS
    SQS_EVENTS = {
        "CreateQueue": {
            "event_type": TimelineEventType.SQS_QUEUE_CREATED,
            "message": "SQS queue created",
            "formatter": EventMessageFormatter.format_sqs_queue_created,
        },
        "DeleteQueue": {
            "event_type": TimelineEventType.SQS_QUEUE_DELETED,
            "message": "SQS queue deleted",
            "formatter": EventMessageFormatter.format_sqs_queue_deleted,
        },
        "SetQueueAttributes": {
            "event_type": TimelineEventType.SQS_QUEUE_ATTRIBUTE_CHANGED,
            "message": "SQS queue attributes changed",
            "formatter": EventMessageFormatter.format_sqs_queue_attribute_changed,
        },
        "AddPermission": {
            "event_type": TimelineEventType.SQS_QUEUE_POLICY_CHANGED,
            "message": "SQS queue policy changed",
            "formatter": EventMessageFormatter.format_sqs_queue_policy_changed,
        },
        "RemovePermission": {
            "event_type": TimelineEventType.SQS_QUEUE_POLICY_CHANGED,
            "message": "SQS queue policy changed",
            "formatter": EventMessageFormatter.format_sqs_queue_policy_changed,
        },
    }

    # Event mappings for ECR
    ECR_EVENTS = {
        "CreateRepository": {
            "event_type": TimelineEventType.ECR_REPOSITORY_CREATED,
            "message": "ECR repository created",
            "formatter": EventMessageFormatter.format_ecr_repository_created,
        },
        "DeleteRepository": {
            "event_type": TimelineEventType.ECR_REPOSITORY_DELETED,
            "message": "ECR repository deleted",
            "formatter": EventMessageFormatter.format_ecr_repository_deleted,
        },
        "PutImage": {
            "event_type": TimelineEventType.ECR_IMAGE_PUSHED,
            "message": "ECR image pushed",
            "formatter": EventMessageFormatter.format_ecr_image_pushed,
        },
        "BatchDeleteImage": {
            "event_type": TimelineEventType.ECR_IMAGE_DELETED,
            "message": "ECR image(s) deleted",
            "formatter": EventMessageFormatter.format_ecr_image_deleted,
        },
        "PutLifecyclePolicy": {
            "event_type": TimelineEventType.ECR_LIFECYCLE_POLICY_SET,
            "message": "ECR lifecycle policy set",
            "formatter": EventMessageFormatter.format_ecr_lifecycle_policy_set,
        },
        "SetRepositoryPolicy": {
            "event_type": TimelineEventType.ECR_REPOSITORY_POLICY_SET,
            "message": "ECR repository policy set",
            "formatter": EventMessageFormatter.format_ecr_repository_policy_set,
        },
        "PutImageScanningConfiguration": {
            "event_type": TimelineEventType.ECR_IMAGE_SCAN_CONFIGURED,
            "message": "ECR image scanning configured",
            "formatter": EventMessageFormatter.format_ecr_image_scan_configured,
        },
    }

    # Event mappings for ECS
    ECS_EVENTS = {
        "CreateCluster": {
            "event_type": TimelineEventType.ECS_CLUSTER_CREATED,
            "message": "ECS cluster created",
            "formatter": EventMessageFormatter.format_ecs_cluster_created,
        },
        "DeleteCluster": {
            "event_type": TimelineEventType.ECS_CLUSTER_DELETED,
            "message": "ECS cluster deleted",
            "formatter": EventMessageFormatter.format_ecs_cluster_deleted,
        },
        "CreateService": {
            "event_type": TimelineEventType.ECS_SERVICE_CREATED,
            "message": "ECS service created",
            "formatter": EventMessageFormatter.format_ecs_service_created,
        },
        "DeleteService": {
            "event_type": TimelineEventType.ECS_SERVICE_DELETED,
            "message": "ECS service deleted",
            "formatter": EventMessageFormatter.format_ecs_service_deleted,
        },
        "UpdateService": {
            "event_type": TimelineEventType.ECS_SERVICE_UPDATED,
            "message": "ECS service updated",
            "formatter": EventMessageFormatter.format_ecs_service_updated,
        },
        "RegisterTaskDefinition": {
            "event_type": TimelineEventType.ECS_TASK_DEFINITION_REGISTERED,
            "message": "ECS task definition registered",
            "formatter": EventMessageFormatter.format_ecs_task_definition_registered,
        },
        "DeregisterTaskDefinition": {
            "event_type": TimelineEventType.ECS_TASK_DEFINITION_DEREGISTERED,
            "message": "ECS task definition deregistered",
            "formatter": EventMessageFormatter.format_ecs_task_definition_deregistered,
        },
    }

    def __init__(
        self,
        lookback_days: int = 90,
    ):
        """Initialize CloudTrail enricher.

        Args:
            lookback_days: Days to look back for events (default: 90, max: 90)
        """
        self.lookback_days = lookback_days

        # Calculate time range based on lookback days
        self.end_time = datetime.now(timezone.utc)
        self.start_time = self.end_time - timedelta(days=self.lookback_days)

    def enrich_finding(self, finding: Any) -> Any:
        """Enrich a single finding with CloudTrail timeline.

        Args:
            finding: Prowler finding object

        Returns:
            Finding with enrichment data added
        """
        try:
            # Extract resource info from finding
            resource_id = getattr(finding, "resource_id", None)
            resource_arn = getattr(finding, "resource_arn", None)
            region = getattr(finding, "region", None)

            if not resource_id:
                logger.info(
                    "Skipping enrichment for finding without resource_id: %s",
                    getattr(finding, "check_metadata", {}).CheckID or "unknown",
                )
                return finding

            if not region:
                logger.info("Skipping enrichment - missing region")
                return finding

            # Determine resource type from ARN or finding metadata
            resource_type = self._determine_resource_type(resource_arn, finding)

            # Query CloudTrail
            timeline_events = self._lookup_resource_events(
                resource_id, resource_type, region
            )
            if not timeline_events:
                logger.info(
                    "No CloudTrail events found for resource %s with type %s",
                    resource_arn,
                    resource_type,
                )
                return finding

            # Create enrichment object
            enrichment = self._create_enrichment(timeline_events)

            # Add enrichment to finding
            finding.enrichment = enrichment

            logger.info(
                "Enriched finding for %s with %d timeline events",
                resource_arn,
                len(timeline_events),
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDeniedException":
                logger.warning(
                    "Missing CloudTrail permissions to enrich findings. "
                    "Add 'cloudtrail:LookupEvents' permission to continue."
                )
            else:
                logger.error(
                    "CloudTrail API error during enrichment: %s - %s",
                    error_code,
                    e.response.get("Error", {}).get("Message", ""),
                )
        except Exception as e:
            logger.error(
                "Failed to enrich finding for %s: %s",
                resource_id,
                str(e),
                exc_info=True,
            )

        return finding

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
                "No supported CloudTrail events for resource type: %s", resource_type
            )
            return []

        timeline_events = []

        try:
            # Import CloudTrail client
            from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
                cloudtrail_client,
            )

            # Query CloudTrail using the client method (gets ALL events, no limit)
            events = cloudtrail_client.lookup_events_for_resource(
                region=region,
                resource_id=resource_id,
                start_time=self.start_time,
                end_time=self.end_time,
            )

            for event in events:
                event_name = event.get("EventName")

                if event_name in supported_events:
                    timeline_event = self._parse_cloudtrail_event(
                        event, resource_id, resource_type, supported_events
                    )
                    if timeline_event:
                        timeline_events.append(timeline_event)

        except ClientError as e:
            logger.error(
                "CloudTrail lookup failed for %s: %s",
                resource_id,
                e.response.get("Error", {}).get("Message", ""),
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
                    "event_type", TimelineEventType.RESOURCE_MODIFIED
                ),
                resource_type=resource_type,
                resource_id=resource_id,
                principal=principal,
                message=message,
                event_details=event_details,
            )

        except Exception as e:
            logger.warning(
                "Failed to parse CloudTrail event %s: %s",
                event.get("EventId", "unknown"),
                str(e),
            )
            return None

    def _create_enrichment(
        self, timeline_events: list[TimelineEvent]
    ) -> FindingEnrichment:
        """Create FindingEnrichment from timeline events.

        Extracts attribution info (who created, who last modified) from events.

        Args:
            timeline_events: List of timeline events

        Returns:
            FindingEnrichment object
        """
        if not timeline_events:
            return FindingEnrichment()

        # Sort events by timestamp
        sorted_events = sorted(timeline_events, key=lambda e: e.timestamp)

        # Extract creation info
        created_by = None
        created_at = None
        for event in sorted_events:
            if event.event_type in [
                TimelineEventType.RESOURCE_CREATED,
                TimelineEventType.INSTANCE_CREATED,
                TimelineEventType.SECURITY_GROUP_CREATED,
                TimelineEventType.NETWORK_INTERFACE_CREATED,
                TimelineEventType.LOAD_BALANCER_CREATED,
                TimelineEventType.RDS_INSTANCE_CREATED,
                TimelineEventType.RDS_CLUSTER_CREATED,
                TimelineEventType.S3_BUCKET_CREATED,
                TimelineEventType.LAMBDA_FUNCTION_CREATED,
                TimelineEventType.VPC_CREATED,
                TimelineEventType.SUBNET_CREATED,
                TimelineEventType.ELBV2_LOAD_BALANCER_CREATED,
                TimelineEventType.IAM_USER_CREATED,
                TimelineEventType.IAM_ROLE_CREATED,
                TimelineEventType.DYNAMODB_TABLE_CREATED,
                TimelineEventType.KMS_KEY_CREATED,
                TimelineEventType.CLOUDTRAIL_TRAIL_CREATED,
                TimelineEventType.EBS_VOLUME_CREATED,
                TimelineEventType.EBS_SNAPSHOT_CREATED,
                TimelineEventType.SECRETS_MANAGER_SECRET_CREATED,
                TimelineEventType.CLOUDWATCH_ALARM_CREATED,
                TimelineEventType.CLOUDWATCH_LOG_GROUP_CREATED,
                TimelineEventType.SNS_TOPIC_CREATED,
                TimelineEventType.SQS_QUEUE_CREATED,
                TimelineEventType.ECR_REPOSITORY_CREATED,
                TimelineEventType.ECS_CLUSTER_CREATED,
                TimelineEventType.ECS_SERVICE_CREATED,
            ]:
                created_by = event.principal
                created_at = event.timestamp
                break

        # Extract last modification info
        last_modified_by = sorted_events[-1].principal if sorted_events else None
        last_modified_at = sorted_events[-1].timestamp if sorted_events else None

        # Extract related resources
        related_resources = []
        seen_resources = set()
        for event in sorted_events:
            resource_key = f"{event.resource_type}:{event.resource_id}"
            if resource_key not in seen_resources:
                related_resources.append(
                    {
                        "resource_type": event.resource_type,
                        "resource_id": event.resource_id,
                    }
                )
                seen_resources.add(resource_key)

        return FindingEnrichment(
            timeline=sorted_events,
            created_by=created_by,
            created_at=created_at,
            last_modified_by=last_modified_by,
            last_modified_at=last_modified_at,
            related_resources=related_resources,
        )

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
            logger.info("Unsupported resource type for enrichment: %s", resource_type)
            return {}

    def _determine_resource_type(self, resource_arn: str | None, finding: Any) -> str:
        """Determine AWS resource type from ARN or finding metadata.

        Args:
            resource_arn: Resource ARN if available
            finding: Prowler finding object

        Returns:
            AWS resource type string (e.g., "AWS::EC2::Instance")
        """
        if resource_arn:
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
                if service == "ec2":
                    if resource_type_part.startswith("instance"):
                        return "AWS::EC2::Instance"
                    elif resource_type_part.startswith("security-group"):
                        return "AWS::EC2::SecurityGroup"
                    elif resource_type_part.startswith("network-interface"):
                        return "AWS::EC2::NetworkInterface"
                    elif resource_type_part.startswith("snapshot"):
                        return "AWS::EC2::Snapshot"
                elif service == "elasticloadbalancing":
                    return "AWS::ElasticLoadBalancingV2::LoadBalancer"
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
                    if (
                        resource_type_part.startswith("topic")
                        or "/" not in resource_part
                    ):
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

            # VPC and EBS resources are under ec2 service
            if service == "ec2":
                if "vpc" in resource_type_part:
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

        # Fall back to check metadata service name
        check_metadata = getattr(finding, "check_metadata", None)
        service_name = (
            getattr(check_metadata, "ServiceName", "") if check_metadata else ""
        )

        if service_name:
            # Map Prowler service names to resource types
            service_map = {
                "ec2": "AWS::EC2::Instance",
                "vpc": "AWS::EC2::VPC",
                "elb": "AWS::ElasticLoadBalancing::LoadBalancer",
                "elbv2": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "rds": "AWS::RDS::DBInstance",
                "s3": "AWS::S3::Bucket",
                "awslambda": "AWS::Lambda::Function",
                "lambda": "AWS::Lambda::Function",
                "iam": "AWS::IAM::Resource",
                "dynamodb": "AWS::DynamoDB::Table",
            }
            return service_map.get(service_name, f"AWS::{service_name}")

        return "AWS::Unknown"
