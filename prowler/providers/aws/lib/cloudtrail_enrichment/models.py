"""Data models for finding enrichment with CloudTrail timeline events."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic.v1 import BaseModel, validator


# General resource events
class GeneralEventType(str, Enum):
    """General resource events."""

    RESOURCE_CREATED = "resource_created"
    RESOURCE_MODIFIED = "resource_modified"
    RESOURCE_DELETED = "resource_deleted"


# EC2 events
class EC2EventType(str, Enum):
    """EC2 Instance and related resource events."""

    INSTANCE_CREATED = "instance_created"
    INSTANCE_TERMINATED = "instance_terminated"
    INSTANCE_STARTED = "instance_started"
    INSTANCE_STOPPED = "instance_stopped"
    INSTANCE_REBOOTED = "instance_rebooted"
    INSTANCE_STATE_CHANGE = "instance_state_change"
    SECURITY_GROUP_CREATED = "security_group_created"
    SECURITY_GROUP_RULE_ADDED = "sg_rule_added"
    SECURITY_GROUP_RULE_MODIFIED = "sg_rule_modified"
    SECURITY_GROUP_RULE_REMOVED = "sg_rule_removed"
    NETWORK_INTERFACE_CREATED = "network_interface_created"
    NETWORK_INTERFACE_MODIFIED = "network_interface_modified"
    NETWORK_INTERFACE_ATTACHED = "network_interface_attached"
    NETWORK_INTERFACE_DETACHED = "network_interface_detached"


# ELB events
class ELBEventType(str, Enum):
    """Elastic Load Balancer events."""

    LOAD_BALANCER_CREATED = "load_balancer_created"
    LOAD_BALANCER_MODIFIED = "load_balancer_modified"
    LOAD_BALANCER_DELETED = "load_balancer_deleted"


# RDS events
class RDSEventType(str, Enum):
    """RDS database and cluster events."""

    INSTANCE_CREATED = "rds_instance_created"
    INSTANCE_MODIFIED = "rds_instance_modified"
    INSTANCE_DELETED = "rds_instance_deleted"
    SNAPSHOT_CREATED = "rds_snapshot_created"
    SNAPSHOT_SHARED = "rds_snapshot_shared"
    CLUSTER_CREATED = "rds_cluster_created"
    CLUSTER_MODIFIED = "rds_cluster_modified"


# S3 events
class S3EventType(str, Enum):
    """S3 bucket configuration events."""

    BUCKET_CREATED = "s3_bucket_created"
    BUCKET_DELETED = "s3_bucket_deleted"
    BUCKET_POLICY_CHANGED = "s3_bucket_policy_changed"
    PUBLIC_ACCESS_BLOCK_CHANGED = "s3_public_access_block_changed"
    ENCRYPTION_CHANGED = "s3_encryption_changed"
    VERSIONING_CHANGED = "s3_versioning_changed"
    LOGGING_CHANGED = "s3_logging_changed"


# Lambda events
class LambdaEventType(str, Enum):
    """Lambda function events."""

    FUNCTION_CREATED = "lambda_function_created"
    FUNCTION_DELETED = "lambda_function_deleted"
    FUNCTION_UPDATED = "lambda_function_updated"
    CODE_UPDATED = "lambda_code_updated"
    PERMISSION_ADDED = "lambda_permission_added"
    FUNCTION_URL_CREATED = "lambda_function_url_created"
    ENVIRONMENT_UPDATED = "lambda_environment_updated"


# VPC events
class VPCEventType(str, Enum):
    """VPC and networking resource events."""

    VPC_CREATED = "vpc_created"
    VPC_MODIFIED = "vpc_modified"
    VPC_DELETED = "vpc_deleted"
    SUBNET_CREATED = "subnet_created"
    SUBNET_MODIFIED = "subnet_modified"
    ROUTE_TABLE_CREATED = "route_table_created"
    ROUTE_CREATED = "route_created"
    INTERNET_GATEWAY_CREATED = "internet_gateway_created"
    INTERNET_GATEWAY_ATTACHED = "internet_gateway_attached"
    NAT_GATEWAY_CREATED = "nat_gateway_created"
    VPC_ENDPOINT_CREATED = "vpc_endpoint_created"
    NETWORK_ACL_CREATED = "network_acl_created"
    NETWORK_ACL_ENTRY_CREATED = "network_acl_entry_created"


# ELBv2 events
class ELBv2EventType(str, Enum):
    """Application and Network Load Balancer events."""

    LOAD_BALANCER_CREATED = "elbv2_load_balancer_created"
    LOAD_BALANCER_MODIFIED = "elbv2_load_balancer_modified"
    LOAD_BALANCER_DELETED = "elbv2_load_balancer_deleted"
    LISTENER_CREATED = "elbv2_listener_created"
    LISTENER_MODIFIED = "elbv2_listener_modified"
    TARGET_GROUP_CREATED = "elbv2_target_group_created"


# IAM events
class IAMEventType(str, Enum):
    """IAM user, role, and policy events."""

    USER_CREATED = "iam_user_created"
    USER_DELETED = "iam_user_deleted"
    ROLE_CREATED = "iam_role_created"
    ROLE_DELETED = "iam_role_deleted"
    POLICY_ATTACHED = "iam_policy_attached"
    POLICY_CREATED = "iam_policy_created"
    ACCESS_KEY_CREATED = "iam_access_key_created"
    USER_ADDED_TO_GROUP = "iam_user_added_to_group"
    ASSUME_ROLE_POLICY_UPDATED = "iam_assume_role_policy_updated"


# DynamoDB events
class DynamoDBEventType(str, Enum):
    """DynamoDB table events."""

    TABLE_CREATED = "dynamodb_table_created"
    TABLE_UPDATED = "dynamodb_table_updated"
    TABLE_DELETED = "dynamodb_table_deleted"
    BACKUP_CREATED = "dynamodb_backup_created"
    PITR_UPDATED = "dynamodb_pitr_updated"


# KMS events
class KMSEventType(str, Enum):
    """KMS key management events."""

    KEY_CREATED = "kms_key_created"
    KEY_DELETED = "kms_key_deleted"
    KEY_DELETION_SCHEDULED = "kms_key_deletion_scheduled"
    KEY_DELETION_CANCELLED = "kms_key_deletion_cancelled"
    KEY_DISABLED = "kms_key_disabled"
    KEY_ENABLED = "kms_key_enabled"
    KEY_ROTATION_ENABLED = "kms_key_rotation_enabled"
    KEY_ROTATION_DISABLED = "kms_key_rotation_disabled"
    KEY_POLICY_CHANGED = "kms_key_policy_changed"
    KEY_IMPORTED = "kms_key_imported"
    GRANT_CREATED = "kms_grant_created"
    GRANT_REVOKED = "kms_grant_revoked"


# CloudTrail events
class CloudTrailEventType(str, Enum):
    """CloudTrail configuration events."""

    TRAIL_CREATED = "cloudtrail_trail_created"
    TRAIL_DELETED = "cloudtrail_trail_deleted"
    TRAIL_UPDATED = "cloudtrail_trail_updated"
    LOGGING_STOPPED = "cloudtrail_logging_stopped"
    LOGGING_STARTED = "cloudtrail_logging_started"
    EVENT_SELECTORS_UPDATED = "cloudtrail_event_selectors_updated"


# EBS events
class EBSEventType(str, Enum):
    """EBS volume and snapshot events."""

    VOLUME_CREATED = "ebs_volume_created"
    VOLUME_DELETED = "ebs_volume_deleted"
    VOLUME_MODIFIED = "ebs_volume_modified"
    SNAPSHOT_CREATED = "ebs_snapshot_created"
    SNAPSHOT_DELETED = "ebs_snapshot_deleted"
    SNAPSHOT_SHARED = "ebs_snapshot_shared"
    ENCRYPTION_ENABLED = "ebs_encryption_enabled"
    ENCRYPTION_DISABLED = "ebs_encryption_disabled"


# Secrets Manager events
class SecretsManagerEventType(str, Enum):
    """Secrets Manager secret events."""

    SECRET_CREATED = "secrets_manager_secret_created"
    SECRET_DELETED = "secrets_manager_secret_deleted"
    SECRET_UPDATED = "secrets_manager_secret_updated"
    SECRET_ROTATED = "secrets_manager_secret_rotated"
    ROTATION_ENABLED = "secrets_manager_rotation_enabled"
    ROTATION_DISABLED = "secrets_manager_rotation_disabled"
    POLICY_CHANGED = "secrets_manager_policy_changed"


# CloudWatch events
class CloudWatchEventType(str, Enum):
    """CloudWatch alarm and log group events."""

    ALARM_CREATED = "cloudwatch_alarm_created"
    ALARM_DELETED = "cloudwatch_alarm_deleted"
    ALARM_UPDATED = "cloudwatch_alarm_updated"
    ALARM_STATE_CHANGED = "cloudwatch_alarm_state_changed"
    ALARM_ACTIONS_DISABLED = "cloudwatch_alarm_actions_disabled"
    ALARM_ACTIONS_ENABLED = "cloudwatch_alarm_actions_enabled"
    LOG_GROUP_CREATED = "cloudwatch_log_group_created"
    LOG_GROUP_DELETED = "cloudwatch_log_group_deleted"
    LOG_RETENTION_CHANGED = "cloudwatch_log_retention_changed"


# SNS events
class SNSEventType(str, Enum):
    """SNS topic and subscription events."""

    TOPIC_CREATED = "sns_topic_created"
    TOPIC_DELETED = "sns_topic_deleted"
    TOPIC_ATTRIBUTE_CHANGED = "sns_topic_attribute_changed"
    SUBSCRIPTION_CREATED = "sns_subscription_created"
    SUBSCRIPTION_DELETED = "sns_subscription_deleted"


# SQS events
class SQSEventType(str, Enum):
    """SQS queue configuration events."""

    QUEUE_CREATED = "sqs_queue_created"
    QUEUE_DELETED = "sqs_queue_deleted"
    QUEUE_ATTRIBUTE_CHANGED = "sqs_queue_attribute_changed"
    QUEUE_POLICY_CHANGED = "sqs_queue_policy_changed"


# ECR events
class ECREventType(str, Enum):
    """ECR repository and image events."""

    REPOSITORY_CREATED = "ecr_repository_created"
    REPOSITORY_DELETED = "ecr_repository_deleted"
    IMAGE_PUSHED = "ecr_image_pushed"
    IMAGE_DELETED = "ecr_image_deleted"
    LIFECYCLE_POLICY_SET = "ecr_lifecycle_policy_set"
    REPOSITORY_POLICY_SET = "ecr_repository_policy_set"
    IMAGE_SCAN_CONFIGURED = "ecr_image_scan_configured"


# ECS events
class ECSEventType(str, Enum):
    """ECS cluster, service, and task definition events."""

    CLUSTER_CREATED = "ecs_cluster_created"
    CLUSTER_DELETED = "ecs_cluster_deleted"
    SERVICE_CREATED = "ecs_service_created"
    SERVICE_DELETED = "ecs_service_deleted"
    SERVICE_UPDATED = "ecs_service_updated"
    TASK_DEFINITION_REGISTERED = "ecs_task_definition_registered"
    TASK_DEFINITION_DEREGISTERED = "ecs_task_definition_deregistered"


# EKS events
class EKSEventType(str, Enum):
    """EKS cluster events."""

    CLUSTER_CREATED = "eks_cluster_created"
    CLUSTER_DELETED = "eks_cluster_deleted"
    CLUSTER_UPDATED = "eks_cluster_updated"


# Backup events
class BackupEventType(str, Enum):
    """AWS Backup events."""

    BACKUP_PLAN_CREATED = "backup_plan_created"
    BACKUP_PLAN_DELETED = "backup_plan_deleted"
    BACKUP_VAULT_CREATED = "backup_vault_created"


# ACM events
class ACMEventType(str, Enum):
    """ACM certificate events."""

    CERTIFICATE_REQUESTED = "acm_certificate_requested"
    CERTIFICATE_IMPORTED = "acm_certificate_imported"
    CERTIFICATE_DELETED = "acm_certificate_deleted"


# EventBridge events
class EventBridgeEventType(str, Enum):
    """EventBridge rule events."""

    RULE_CREATED = "eventbridge_rule_created"
    RULE_DELETED = "eventbridge_rule_deleted"
    RULE_UPDATED = "eventbridge_rule_updated"


class TimelineEvent(BaseModel):
    """Represents a single event in the resource timeline from CloudTrail.

    Attributes:
        timestamp: When the event occurred (UTC)
        event_source: Source of the event (e.g., "AWS CloudTrail")
        event_type: Type of event (creation, modification, etc.)
        resource_type: AWS resource type (e.g., "AWS::EC2::Instance")
        resource_id: ID of the resource this event relates to
        principal: Who performed the action (IAM user/role ARN or friendly name)
        message: Human-readable description of what happened
        event_details: Full CloudTrail event for detailed analysis
    """

    timestamp: datetime
    event_source: str
    event_type: (
        GeneralEventType
        | EC2EventType
        | ELBEventType
        | RDSEventType
        | S3EventType
        | LambdaEventType
        | VPCEventType
        | ELBv2EventType
        | IAMEventType
        | DynamoDBEventType
        | KMSEventType
        | CloudTrailEventType
        | EBSEventType
        | SecretsManagerEventType
        | CloudWatchEventType
        | SNSEventType
        | SQSEventType
        | ECREventType
        | ECSEventType
        | EKSEventType
        | BackupEventType
        | ACMEventType
        | EventBridgeEventType
    )
    resource_type: str
    resource_id: str
    principal: str
    message: str
    event_details: dict[str, Any] = {}

    @validator("timestamp", pre=True)
    def ensure_timezone_aware(cls, v):
        """Ensure timestamp is timezone-aware UTC."""
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v


class FindingEnrichment(BaseModel):
    """Enrichment data added to a finding from CloudTrail timeline.

    Attributes:
        timeline: List of timeline events for this resource
        created_by: Who created the resource (if known)
        created_at: When the resource was created (if known)
        last_modified_by: Who last modified the resource (if known)
        last_modified_at: When the resource was last modified (if known)
        related_resources: Other resources involved in timeline events
    """

    timeline: list[TimelineEvent] = []
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    last_modified_by: Optional[str] = None
    last_modified_at: Optional[datetime] = None
    related_resources: list[dict[str, str]] = []

    def get_age_days(self) -> Optional[int]:
        """Get the age of the resource in days since creation."""
        if not self.created_at:
            return None

        now = datetime.now(timezone.utc)
        delta = now - self.created_at
        return delta.days

    def get_exposure_duration_days(self) -> Optional[int]:
        """Get how many days the resource has been in its current state.

        This is useful for determining how long a misconfiguration has existed.
        """
        if not self.last_modified_at:
            return None

        now = datetime.now(timezone.utc)
        delta = now - self.last_modified_at
        return delta.days
