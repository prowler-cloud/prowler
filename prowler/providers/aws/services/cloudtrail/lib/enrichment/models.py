"""Data models for finding enrichment with CloudTrail timeline events."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class TimelineEventType(str, Enum):
    """Types of timeline events from CloudTrail."""

    # General resource events
    RESOURCE_CREATED = "resource_created"
    RESOURCE_MODIFIED = "resource_modified"
    RESOURCE_DELETED = "resource_deleted"

    # EC2 Instance events
    INSTANCE_CREATED = "instance_created"
    INSTANCE_TERMINATED = "instance_terminated"
    INSTANCE_STARTED = "instance_started"
    INSTANCE_STOPPED = "instance_stopped"
    INSTANCE_REBOOTED = "instance_rebooted"
    INSTANCE_STATE_CHANGE = "instance_state_change"

    # Security Group events
    SECURITY_GROUP_CREATED = "security_group_created"
    SECURITY_GROUP_RULE_ADDED = "sg_rule_added"
    SECURITY_GROUP_RULE_MODIFIED = "sg_rule_modified"
    SECURITY_GROUP_RULE_REMOVED = "sg_rule_removed"

    # Network Interface events
    NETWORK_INTERFACE_CREATED = "network_interface_created"
    NETWORK_INTERFACE_MODIFIED = "network_interface_modified"
    NETWORK_INTERFACE_ATTACHED = "network_interface_attached"
    NETWORK_INTERFACE_DETACHED = "network_interface_detached"

    # Load Balancer events
    LOAD_BALANCER_CREATED = "load_balancer_created"
    LOAD_BALANCER_MODIFIED = "load_balancer_modified"
    LOAD_BALANCER_DELETED = "load_balancer_deleted"

    # RDS events
    RDS_INSTANCE_CREATED = "rds_instance_created"
    RDS_INSTANCE_MODIFIED = "rds_instance_modified"
    RDS_INSTANCE_DELETED = "rds_instance_deleted"
    RDS_SNAPSHOT_CREATED = "rds_snapshot_created"
    RDS_SNAPSHOT_SHARED = "rds_snapshot_shared"
    RDS_CLUSTER_CREATED = "rds_cluster_created"
    RDS_CLUSTER_MODIFIED = "rds_cluster_modified"

    # S3 events
    S3_BUCKET_CREATED = "s3_bucket_created"
    S3_BUCKET_DELETED = "s3_bucket_deleted"
    S3_BUCKET_POLICY_CHANGED = "s3_bucket_policy_changed"
    S3_PUBLIC_ACCESS_BLOCK_CHANGED = "s3_public_access_block_changed"
    S3_ENCRYPTION_CHANGED = "s3_encryption_changed"
    S3_VERSIONING_CHANGED = "s3_versioning_changed"
    S3_LOGGING_CHANGED = "s3_logging_changed"

    # Lambda events
    LAMBDA_FUNCTION_CREATED = "lambda_function_created"
    LAMBDA_FUNCTION_DELETED = "lambda_function_deleted"
    LAMBDA_FUNCTION_UPDATED = "lambda_function_updated"
    LAMBDA_CODE_UPDATED = "lambda_code_updated"
    LAMBDA_PERMISSION_ADDED = "lambda_permission_added"
    LAMBDA_FUNCTION_URL_CREATED = "lambda_function_url_created"
    LAMBDA_ENVIRONMENT_UPDATED = "lambda_environment_updated"

    # VPC events
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
    ELBV2_LOAD_BALANCER_CREATED = "elbv2_load_balancer_created"
    ELBV2_LOAD_BALANCER_MODIFIED = "elbv2_load_balancer_modified"
    ELBV2_LOAD_BALANCER_DELETED = "elbv2_load_balancer_deleted"
    ELBV2_LISTENER_CREATED = "elbv2_listener_created"
    ELBV2_LISTENER_MODIFIED = "elbv2_listener_modified"
    ELBV2_TARGET_GROUP_CREATED = "elbv2_target_group_created"

    # IAM events
    IAM_USER_CREATED = "iam_user_created"
    IAM_USER_DELETED = "iam_user_deleted"
    IAM_ROLE_CREATED = "iam_role_created"
    IAM_ROLE_DELETED = "iam_role_deleted"
    IAM_POLICY_ATTACHED = "iam_policy_attached"
    IAM_POLICY_CREATED = "iam_policy_created"
    IAM_ACCESS_KEY_CREATED = "iam_access_key_created"
    IAM_USER_ADDED_TO_GROUP = "iam_user_added_to_group"
    IAM_ASSUME_ROLE_POLICY_UPDATED = "iam_assume_role_policy_updated"

    # DynamoDB events
    DYNAMODB_TABLE_CREATED = "dynamodb_table_created"
    DYNAMODB_TABLE_UPDATED = "dynamodb_table_updated"
    DYNAMODB_TABLE_DELETED = "dynamodb_table_deleted"
    DYNAMODB_BACKUP_CREATED = "dynamodb_backup_created"
    DYNAMODB_PITR_UPDATED = "dynamodb_pitr_updated"

    # KMS events
    KMS_KEY_CREATED = "kms_key_created"
    KMS_KEY_DELETED = "kms_key_deleted"
    KMS_KEY_DELETION_SCHEDULED = "kms_key_deletion_scheduled"
    KMS_KEY_DELETION_CANCELLED = "kms_key_deletion_cancelled"
    KMS_KEY_DISABLED = "kms_key_disabled"
    KMS_KEY_ENABLED = "kms_key_enabled"
    KMS_KEY_ROTATION_ENABLED = "kms_key_rotation_enabled"
    KMS_KEY_ROTATION_DISABLED = "kms_key_rotation_disabled"
    KMS_KEY_POLICY_CHANGED = "kms_key_policy_changed"
    KMS_KEY_IMPORTED = "kms_key_imported"
    KMS_GRANT_CREATED = "kms_grant_created"
    KMS_GRANT_REVOKED = "kms_grant_revoked"

    # CloudTrail events
    CLOUDTRAIL_TRAIL_CREATED = "cloudtrail_trail_created"
    CLOUDTRAIL_TRAIL_DELETED = "cloudtrail_trail_deleted"
    CLOUDTRAIL_TRAIL_UPDATED = "cloudtrail_trail_updated"
    CLOUDTRAIL_LOGGING_STOPPED = "cloudtrail_logging_stopped"
    CLOUDTRAIL_LOGGING_STARTED = "cloudtrail_logging_started"
    CLOUDTRAIL_EVENT_SELECTORS_UPDATED = "cloudtrail_event_selectors_updated"

    # EBS events
    EBS_VOLUME_CREATED = "ebs_volume_created"
    EBS_VOLUME_DELETED = "ebs_volume_deleted"
    EBS_VOLUME_MODIFIED = "ebs_volume_modified"
    EBS_SNAPSHOT_CREATED = "ebs_snapshot_created"
    EBS_SNAPSHOT_DELETED = "ebs_snapshot_deleted"
    EBS_SNAPSHOT_SHARED = "ebs_snapshot_shared"
    EBS_ENCRYPTION_ENABLED = "ebs_encryption_enabled"
    EBS_ENCRYPTION_DISABLED = "ebs_encryption_disabled"

    # Secrets Manager events
    SECRETS_MANAGER_SECRET_CREATED = "secrets_manager_secret_created"
    SECRETS_MANAGER_SECRET_DELETED = "secrets_manager_secret_deleted"
    SECRETS_MANAGER_SECRET_UPDATED = "secrets_manager_secret_updated"
    SECRETS_MANAGER_SECRET_ROTATED = "secrets_manager_secret_rotated"
    SECRETS_MANAGER_ROTATION_ENABLED = "secrets_manager_rotation_enabled"
    SECRETS_MANAGER_ROTATION_DISABLED = "secrets_manager_rotation_disabled"
    SECRETS_MANAGER_POLICY_CHANGED = "secrets_manager_policy_changed"

    # CloudWatch events
    CLOUDWATCH_ALARM_CREATED = "cloudwatch_alarm_created"
    CLOUDWATCH_ALARM_DELETED = "cloudwatch_alarm_deleted"
    CLOUDWATCH_ALARM_UPDATED = "cloudwatch_alarm_updated"
    CLOUDWATCH_ALARM_STATE_CHANGED = "cloudwatch_alarm_state_changed"
    CLOUDWATCH_ALARM_ACTIONS_DISABLED = "cloudwatch_alarm_actions_disabled"
    CLOUDWATCH_ALARM_ACTIONS_ENABLED = "cloudwatch_alarm_actions_enabled"
    CLOUDWATCH_LOG_GROUP_CREATED = "cloudwatch_log_group_created"
    CLOUDWATCH_LOG_GROUP_DELETED = "cloudwatch_log_group_deleted"
    CLOUDWATCH_LOG_RETENTION_CHANGED = "cloudwatch_log_retention_changed"

    # SNS events
    SNS_TOPIC_CREATED = "sns_topic_created"
    SNS_TOPIC_DELETED = "sns_topic_deleted"
    SNS_TOPIC_ATTRIBUTE_CHANGED = "sns_topic_attribute_changed"
    SNS_SUBSCRIPTION_CREATED = "sns_subscription_created"
    SNS_SUBSCRIPTION_DELETED = "sns_subscription_deleted"

    # SQS events
    SQS_QUEUE_CREATED = "sqs_queue_created"
    SQS_QUEUE_DELETED = "sqs_queue_deleted"
    SQS_QUEUE_ATTRIBUTE_CHANGED = "sqs_queue_attribute_changed"
    SQS_QUEUE_POLICY_CHANGED = "sqs_queue_policy_changed"

    # ECR events
    ECR_REPOSITORY_CREATED = "ecr_repository_created"
    ECR_REPOSITORY_DELETED = "ecr_repository_deleted"
    ECR_IMAGE_PUSHED = "ecr_image_pushed"
    ECR_IMAGE_DELETED = "ecr_image_deleted"
    ECR_LIFECYCLE_POLICY_SET = "ecr_lifecycle_policy_set"
    ECR_REPOSITORY_POLICY_SET = "ecr_repository_policy_set"
    ECR_IMAGE_SCAN_CONFIGURED = "ecr_image_scan_configured"

    # ECS events
    ECS_CLUSTER_CREATED = "ecs_cluster_created"
    ECS_CLUSTER_DELETED = "ecs_cluster_deleted"
    ECS_SERVICE_CREATED = "ecs_service_created"
    ECS_SERVICE_DELETED = "ecs_service_deleted"
    ECS_SERVICE_UPDATED = "ecs_service_updated"
    ECS_TASK_DEFINITION_REGISTERED = "ecs_task_definition_registered"
    ECS_TASK_DEFINITION_DEREGISTERED = "ecs_task_definition_deregistered"


@dataclass
class TimelineEvent:
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
    event_type: TimelineEventType
    resource_type: str
    resource_id: str
    principal: str
    message: str
    event_details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Ensure timestamp is timezone-aware UTC."""
        if self.timestamp.tzinfo is None:
            from datetime import timezone

            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_source": self.event_source,
            "event_type": self.event_type.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "principal": self.principal,
            "message": self.message,
            "event_details": self.event_details,
        }


@dataclass
class FindingEnrichment:
    """Enrichment data added to a finding from CloudTrail timeline.

    Attributes:
        timeline: List of timeline events for this resource
        created_by: Who created the resource (if known)
        created_at: When the resource was created (if known)
        last_modified_by: Who last modified the resource (if known)
        last_modified_at: When the resource was last modified (if known)
        related_resources: Other resources involved in timeline events
    """

    timeline: list[TimelineEvent] = field(default_factory=list)
    created_by: str | None = None
    created_at: datetime | None = None
    last_modified_by: str | None = None
    last_modified_at: datetime | None = None
    related_resources: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timeline": [event.to_dict() for event in self.timeline],
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_modified_by": self.last_modified_by,
            "last_modified_at": (
                self.last_modified_at.isoformat() if self.last_modified_at else None
            ),
            "related_resources": self.related_resources,
        }

    def get_age_days(self) -> int | None:
        """Get the age of the resource in days since creation."""
        if not self.created_at:
            return None

        from datetime import timezone

        now = datetime.now(timezone.utc)
        delta = now - self.created_at
        return delta.days

    def get_exposure_duration_days(self) -> int | None:
        """Get how many days the resource has been in its current state.

        This is useful for determining how long a misconfiguration has existed.
        """
        if not self.last_modified_at:
            return None

        from datetime import timezone

        now = datetime.now(timezone.utc)
        delta = now - self.last_modified_at
        return delta.days
