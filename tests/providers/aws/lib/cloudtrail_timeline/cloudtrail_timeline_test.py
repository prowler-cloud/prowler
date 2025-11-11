"""Comprehensive tests for CloudTrailTimeline using moto."""

import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.lib.cloudtrail_timeline.cloudtrail_timeline import (
    CloudTrailTimeline,
)
from prowler.providers.aws.lib.cloudtrail_timeline.models import EC2EventType


class TestCloudTrailTimeline:
    """Tests for CloudTrailTimeline class."""

    def test_timeline_initialization(self):
        """Test CloudTrailTimeline initialization."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session, lookback_days=30)

        assert timeline.session == mock_session
        assert timeline.lookback_days == 30
        assert timeline.start_time is not None
        assert timeline.end_time is not None

    def test_timeline_default_lookback_days(self):
        """Test default lookback period is 90 days."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        assert timeline.lookback_days == 90

    def test_get_resource_timeline_no_resource_id(self):
        """Test timeline retrieval returns empty list when resource_id is missing."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        result = timeline.get_resource_timeline(
            "", "arn:aws:ec2:us-east-1:123:sg/test", "us-east-1"
        )

        assert result == []

    def test_get_resource_timeline_no_region(self):
        """Test timeline retrieval returns empty list when region is missing."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        result = timeline.get_resource_timeline(
            "sg-123", "arn:aws:ec2:us-east-1:123:sg/test", ""
        )

        assert result == []

    @patch(
        "prowler.providers.aws.lib.cloudtrail_timeline.cloudtrail_timeline.CloudTrailTimeline._lookup_resource_events"
    )
    def test_get_resource_timeline_no_events_found(self, mock_lookup):
        """Test timeline retrieval returns empty list when no events found."""
        mock_lookup.return_value = []

        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        result = timeline.get_resource_timeline(
            "sg-123",
            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
            "us-east-1",
        )

        assert result == []

    @patch(
        "prowler.providers.aws.lib.cloudtrail_timeline.cloudtrail_timeline.CloudTrailTimeline._lookup_resource_events"
    )
    def test_get_resource_timeline_with_events(self, mock_lookup):
        """Test timeline retrieval returns list of event dictionaries."""
        from prowler.providers.aws.lib.cloudtrail_timeline.models import TimelineEvent

        mock_events = [
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                event_source="AWS CloudTrail",
                event_type=EC2EventType.SECURITY_GROUP_CREATED,
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="sg-123",
                principal="arn:aws:iam::123456789012:user/admin",
                message="Security group created",
            ),
            TimelineEvent(
                timestamp=datetime(2024, 1, 15, 14, 20, 0, tzinfo=timezone.utc),
                event_source="AWS CloudTrail",
                event_type=EC2EventType.SECURITY_GROUP_RULE_ADDED,
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="sg-123",
                principal="arn:aws:iam::123456789012:user/admin",
                message="Security group rule added",
            ),
        ]
        mock_lookup.return_value = mock_events

        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        result = timeline.get_resource_timeline(
            "sg-123",
            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
            "us-east-1",
        )

        assert len(result) == 2
        assert result[0]["event_type"] == "security_group_created"
        assert result[0]["resource_id"] == "sg-123"
        assert result[1]["event_type"] == "sg_rule_added"

    def test_get_resource_timeline_access_denied(self):
        """Test timeline retrieval handles AccessDeniedException gracefully."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        # Mock CloudTrail client to raise AccessDeniedException
        with patch.object(timeline, "_lookup_resource_events") as mock_lookup:
            error_response = {"Error": {"Code": "AccessDeniedException"}}
            mock_lookup.side_effect = ClientError(error_response, "LookupEvents")

            result = timeline.get_resource_timeline(
                "sg-123",
                "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
                "us-east-1",
            )

            assert result == []

    def test_get_resource_timeline_generic_exception(self):
        """Test timeline retrieval handles generic exceptions gracefully."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        with patch.object(timeline, "_lookup_resource_events") as mock_lookup:
            mock_lookup.side_effect = Exception("Unexpected error")

            result = timeline.get_resource_timeline(
                "sg-123",
                "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
                "us-east-1",
            )

            assert result == []


class TestResourceTypeDetection:
    """Tests for resource type detection from ARN."""

    def test_determine_resource_type_ec2_instance(self):
        """Test EC2 instance ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
        )

        assert resource_type == "AWS::EC2::Instance"

    def test_determine_resource_type_security_group(self):
        """Test security group ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1234567890abcdef0"
        )

        assert resource_type == "AWS::EC2::SecurityGroup"

    def test_determine_resource_type_s3_bucket(self):
        """Test S3 bucket ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:s3:::my-bucket"
        )

        assert resource_type == "AWS::S3::Bucket"

    def test_determine_resource_type_lambda_function(self):
        """Test Lambda function ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:lambda:us-east-1:123456789012:function:my-function"
        )

        assert resource_type == "AWS::Lambda::Function"

    def test_determine_resource_type_iam_role(self):
        """Test IAM role ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:iam::123456789012:role/my-role"
        )

        assert resource_type == "AWS::IAM::Role"

    def test_determine_resource_type_iam_user(self):
        """Test IAM user ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:iam::123456789012:user/my-user"
        )

        assert resource_type == "AWS::IAM::User"

    def test_determine_resource_type_rds_instance(self):
        """Test RDS instance ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:rds:us-east-1:123456789012:db:my-database"
        )

        assert resource_type == "AWS::RDS::DBInstance"

    def test_determine_resource_type_rds_cluster(self):
        """Test RDS cluster ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:rds:us-east-1:123456789012:db-cluster:my-cluster"
        )

        assert resource_type == "AWS::RDS::DBCluster"

    def test_determine_resource_type_kms_key(self):
        """Test KMS key ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        )

        assert resource_type == "AWS::KMS::Key"

    def test_determine_resource_type_vpc(self):
        """Test VPC ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1234567890abcdef0"
        )

        assert resource_type == "AWS::EC2::VPC"

    def test_determine_resource_type_subnet(self):
        """Test subnet ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-1234567890abcdef0"
        )

        assert resource_type == "AWS::EC2::Subnet"

    def test_determine_resource_type_dynamodb_table(self):
        """Test DynamoDB table ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:dynamodb:us-east-1:123456789012:table/my-table"
        )

        assert resource_type == "AWS::DynamoDB::Table"

    def test_determine_resource_type_secrets_manager_secret(self):
        """Test Secrets Manager secret ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-abc123"
        )

        assert resource_type == "AWS::SecretsManager::Secret"

    def test_determine_resource_type_sns_topic(self):
        """Test SNS topic ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:sns:us-east-1:123456789012:my-topic"
        )

        assert resource_type == "AWS::SNS::Topic"

    def test_determine_resource_type_sqs_queue(self):
        """Test SQS queue ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:sqs:us-east-1:123456789012:my-queue"
        )

        assert resource_type == "AWS::SQS::Queue"

    def test_determine_resource_type_ecr_repository(self):
        """Test ECR repository ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ecr:us-east-1:123456789012:repository/my-repo"
        )

        assert resource_type == "AWS::ECR::Repository"

    def test_determine_resource_type_ecs_cluster(self):
        """Test ECS cluster ARN detection."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn(
            "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster"
        )

        assert resource_type == "AWS::ECS::Cluster"

    def test_determine_resource_type_empty_arn(self):
        """Test empty ARN returns Unknown."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn("")

        assert resource_type == "AWS::Unknown"

    def test_determine_resource_type_invalid_arn(self):
        """Test invalid ARN returns Unknown."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session)

        resource_type = timeline._determine_resource_type_from_arn("invalid-arn")

        assert resource_type == "AWS::Unknown"


class TestLookupConfiguration:
    """Tests for CloudTrail lookup configuration."""

    def test_lookup_uses_correct_time_range(self):
        """Test that timeline uses correct lookback period."""
        mock_session = Mock()
        mock_session.region_name = "us-east-1"
        timeline = CloudTrailTimeline(session=mock_session, lookback_days=30)

        # Verify time range is set correctly
        assert timeline.lookback_days == 30
        assert timeline.start_time is not None
        assert timeline.end_time is not None

        # Verify the time difference is approximately 30 days
        time_diff = timeline.end_time - timeline.start_time
        assert abs(time_diff.days - 30) <= 1  # Allow 1 day tolerance


# Integration tests using moto
@mock_aws
class TestCloudTrailTimelineIntegration:
    """Integration tests using moto to mock AWS services."""

    def test_get_resource_timeline_with_real_cloudtrail_client(self):
        """Test timeline retrieval with actual boto3 CloudTrail client (mocked by moto)."""
        # Create real boto3 session (mocked by moto)
        session = boto3.Session(region_name="us-east-1")

        # Create enricher
        timeline = CloudTrailTimeline(session=session, lookback_days=30)

        # Test with a security group
        timeline_events = timeline.get_resource_timeline(
            resource_id="sg-123",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
            region="us-east-1",
        )

        # Should return empty list since moto doesn't have events
        assert isinstance(timeline_events, list)
        assert timeline_events == []

    def test_get_resource_timeline_creates_regional_clients(self):
        """Test that timeline creates CloudTrail clients for different regions."""
        session = boto3.Session(region_name="us-east-1")
        timeline = CloudTrailTimeline(session=session, lookback_days=7)

        # Test with different regions
        for region in ["us-east-1", "eu-west-1", "ap-southeast-1"]:
            timeline_events = timeline.get_resource_timeline(
                resource_id="sg-test",
                resource_arn=f"arn:aws:ec2:{region}:123456789012:security-group/sg-test",
                region=region,
            )

            # Should handle all regions without error
            assert isinstance(timeline_events, list)

    def test_get_resource_timeline_returns_json_serializable(self):
        """Test that returned events are JSON serializable."""
        session = boto3.Session(region_name="us-east-1")
        timeline = CloudTrailTimeline(session=session)

        timeline_events = timeline.get_resource_timeline(
            resource_id="sg-123",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-123",
            region="us-east-1",
        )

        # Should be JSON serializable
        try:
            json.dumps(timeline_events)
        except (TypeError, ValueError):
            pytest.fail("Timeline events are not JSON serializable")

    def test_multiple_timelines_with_same_instance(self):
        """Test that one timeline instance can handle multiple resources."""
        session = boto3.Session(region_name="us-east-1")
        timeline = CloudTrailTimeline(session=session, lookback_days=30)

        # Test multiple resources
        resources = [
            ("sg-123", "arn:aws:ec2:us-east-1:123456789012:security-group/sg-123"),
            ("i-456", "arn:aws:ec2:us-east-1:123456789012:instance/i-456"),
            ("my-bucket", "arn:aws:s3:::my-bucket"),
        ]

        for resource_id, resource_arn in resources:
            timeline_events = timeline.get_resource_timeline(
                resource_id=resource_id,
                resource_arn=resource_arn,
                region="us-east-1",
            )

            # Each should work independently
            assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineWithEC2:
    """Integration tests with EC2 resources created via moto."""

    def test_timeline_ec2_instance(self):
        """Test enriching an EC2 instance created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create EC2 instance using moto
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.run_instances(ImageId="ami-12345", MinCount=1, MaxCount=1)
        instance_id = response["Instances"][0]["InstanceId"]

        # Enrich the instance
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=instance_id,
            resource_arn=f"arn:aws:ec2:us-east-1:123456789012:instance/{instance_id}",
            region="us-east-1",
        )

        # Should return a list (may be empty since moto's CloudTrail is limited)
        assert isinstance(timeline_events, list)

    def test_timeline_security_group(self):
        """Test enriching a security group created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create security group using moto
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test security group",
        )
        sg_id = response["GroupId"]

        # Enrich the security group
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=sg_id,
            resource_arn=f"arn:aws:ec2:us-east-1:123456789012:security-group/{sg_id}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)

    def test_timeline_vpc(self):
        """Test enriching a VPC created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create VPC using moto
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = response["Vpc"]["VpcId"]

        # Enrich the VPC
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=vpc_id,
            resource_arn=f"arn:aws:ec2:us-east-1:123456789012:vpc/{vpc_id}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineWithS3:
    """Integration tests with S3 resources created via moto."""

    def test_timeline_s3_bucket(self):
        """Test enriching an S3 bucket created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create S3 bucket using moto
        s3 = session.client("s3", region_name="us-east-1")
        bucket_name = "test-bucket-12345"
        s3.create_bucket(Bucket=bucket_name)

        # Enrich the bucket
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=bucket_name,
            resource_arn=f"arn:aws:s3:::{bucket_name}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineWithIAM:
    """Integration tests with IAM resources created via moto."""

    def test_timeline_iam_role(self):
        """Test enriching an IAM role created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create IAM role using moto
        iam = session.client("iam", region_name="us-east-1")
        role_name = "test-role"
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
        )

        # Enrich the role
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=role_name,
            resource_arn=f"arn:aws:iam::123456789012:role/{role_name}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)

    def test_timeline_iam_user(self):
        """Test enriching an IAM user created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create IAM user using moto
        iam = session.client("iam", region_name="us-east-1")
        user_name = "test-user"
        iam.create_user(UserName=user_name)

        # Enrich the user
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=user_name,
            resource_arn=f"arn:aws:iam::123456789012:user/{user_name}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineWithRDS:
    """Integration tests with RDS resources created via moto."""

    def test_timeline_rds_instance(self):
        """Test enriching an RDS instance created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create RDS instance using moto
        rds = session.client("rds", region_name="us-east-1")
        db_name = "test-db"
        rds.create_db_instance(
            DBInstanceIdentifier=db_name,
            DBInstanceClass="db.t2.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
        )

        # Enrich the RDS instance
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=db_name,
            resource_arn=f"arn:aws:rds:us-east-1:123456789012:db:{db_name}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineWithLambda:
    """Integration tests with Lambda resources created via moto."""

    def test_timeline_lambda_function(self):
        """Test enriching a Lambda function created with moto."""
        session = boto3.Session(region_name="us-east-1")

        # Create Lambda function using moto
        lambda_client = session.client("lambda", region_name="us-east-1")
        function_name = "test-function"

        # Create IAM role first
        iam = session.client("iam", region_name="us-east-1")
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_response = iam.create_role(
            RoleName="test-lambda-role",
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
        )
        role_arn = role_response["Role"]["Arn"]

        # Create Lambda function
        lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.9",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fake code"},
        )

        # Enrich the Lambda function
        timeline = CloudTrailTimeline(session=session, lookback_days=7)
        timeline_events = timeline.get_resource_timeline(
            resource_id=function_name,
            resource_arn=f"arn:aws:lambda:us-east-1:123456789012:function:{function_name}",
            region="us-east-1",
        )

        # Should return a list
        assert isinstance(timeline_events, list)


@mock_aws
class TestCloudTrailTimelineErrorHandling:
    """Integration tests for error handling scenarios with moto."""

    def test_timeline_nonexistent_resource(self):
        """Test enriching a resource that doesn't exist."""
        session = boto3.Session(region_name="us-east-1")
        timeline = CloudTrailTimeline(session=session)

        # Try to enrich non-existent resource
        timeline_events = timeline.get_resource_timeline(
            resource_id="sg-nonexistent",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-nonexistent",
            region="us-east-1",
        )

        # Should handle gracefully and return empty list
        assert timeline_events == []

    def test_timeline_with_malformed_arn(self):
        """Test enriching with a malformed ARN."""
        session = boto3.Session(region_name="us-east-1")
        timeline = CloudTrailTimeline(session=session)

        # Try with malformed ARN
        timeline_events = timeline.get_resource_timeline(
            resource_id="test-resource",
            resource_arn="not-a-valid-arn",
            region="us-east-1",
        )

        # Should handle gracefully
        assert isinstance(timeline_events, list)
