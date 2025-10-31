"""Unit tests for CloudTrail event message formatters."""

from prowler.providers.aws.services.cloudtrail.lib.enrichment.formatters import (
    EventMessageFormatter,
)


class TestEventMessageFormatter:
    """Tests for event message formatting."""

    def test_format_security_group_rule_added(self):
        """Test formatting AuthorizeSecurityGroupIngress event."""
        event = {
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                        }
                    ]
                }
            }
        }

        message = EventMessageFormatter.format_security_group_rule_added(event)

        assert "Ingress rule added:" in message
        assert "0.0.0.0/0:22" in message
        assert "tcp" in message

    def test_format_security_group_rule_added_port_range(self):
        """Test formatting rule with port range."""
        event = {
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 80,
                            "toPort": 443,
                            "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
                        }
                    ]
                }
            }
        }

        message = EventMessageFormatter.format_security_group_rule_added(event)

        assert "10.0.0.0/8:80-443" in message or "10.0.0.0/8" in message

    def test_format_security_group_rule_added_ipv6(self):
        """Test formatting rule with IPv6 CIDR."""
        event = {
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 443,
                            "toPort": 443,
                            "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
                        }
                    ]
                }
            }
        }

        message = EventMessageFormatter.format_security_group_rule_added(event)

        assert "::/0" in message
        assert "443" in message

    def test_format_instance_created(self):
        """Test formatting RunInstances event."""
        event = {
            "requestParameters": {
                "instanceType": "t3.medium",
                "imageId": "ami-0abc123",
                "networkInterfaceSet": {
                    "items": [
                        {
                            "groupSet": {
                                "items": [
                                    {"groupId": "sg-0abc123"},
                                    {"groupId": "sg-0def456"},
                                ]
                            }
                        }
                    ]
                },
            }
        }

        message = EventMessageFormatter.format_instance_created(event)

        assert "t3.medium" in message
        assert "ami-0abc123" in message
        assert "sg-0abc123" in message
        assert "sg-0def456" in message

    def test_format_instance_created_no_security_groups(self):
        """Test formatting instance creation without security groups."""
        event = {
            "requestParameters": {
                "instanceType": "t2.micro",
                "imageId": "ami-test",
            }
        }

        message = EventMessageFormatter.format_instance_created(event)

        assert "t2.micro" in message
        assert "ami-test" in message

    def test_format_eni_attribute_modification_security_groups(self):
        """Test formatting ENI modification with security group change."""
        event = {
            "requestParameters": {
                "groupSet": {
                    "items": [
                        {"groupId": "sg-new123"},
                        {"groupId": "sg-new456"},
                    ]
                }
            }
        }

        message = EventMessageFormatter.format_eni_attribute_modification(event)

        assert "Security groups updated:" in message
        assert "sg-new123" in message
        assert "sg-new456" in message

    def test_format_eni_attribute_modification_source_dest_check(self):
        """Test formatting ENI source/dest check modification."""
        event = {"requestParameters": {"sourceDestCheck": {"value": False}}}

        message = EventMessageFormatter.format_eni_attribute_modification(event)

        assert "Source/destination check" in message
        assert "False" in message

    def test_format_load_balancer_created(self):
        """Test formatting CreateLoadBalancer event."""
        event = {
            "requestParameters": {
                "name": "my-load-balancer",
                "type": "application",
                "scheme": "internet-facing",
            }
        }

        message = EventMessageFormatter.format_load_balancer_created(event)

        assert "my-load-balancer" in message
        assert "application" in message
        assert "internet-facing" in message

    def test_extract_principal_name_iam_user(self):
        """Test extracting principal from IAM user event."""
        event = {
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin",
                "arn": "arn:aws:iam::123456789012:user/admin",
            }
        }

        principal = EventMessageFormatter.extract_principal_name(event)

        assert principal == "admin"

    def test_extract_principal_name_assumed_role(self):
        """Test extracting principal from assumed role event."""
        event = {
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AIDAI1234567890ABCDEF:admin@company.com",
                "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/admin@company.com",
                "sessionContext": {"sessionIssuer": {"userName": "AdminRole"}},
            }
        }

        principal = EventMessageFormatter.extract_principal_name(event)

        # Should extract the session name from principalId
        assert "admin@company.com" in principal

    def test_extract_principal_name_from_arn(self):
        """Test extracting principal from ARN when other fields unavailable."""
        event = {
            "userIdentity": {
                "type": "Root",
                "arn": "arn:aws:iam::123456789012:root",
            }
        }

        principal = EventMessageFormatter.extract_principal_name(event)

        assert "root" in principal

    def test_extract_principal_name_fallback(self):
        """Test principal extraction fallback to type."""
        event = {"userIdentity": {"type": "AWSService"}}

        principal = EventMessageFormatter.extract_principal_name(event)

        assert principal == "AWSService"

    def test_format_rds_instance_created(self):
        """Test formatting CreateDBInstance event."""
        event = {
            "requestParameters": {
                "dBInstanceIdentifier": "my-database",
                "dBInstanceClass": "db.t3.medium",
                "engine": "postgres",
                "publiclyAccessible": True,
                "storageEncrypted": False,
            }
        }

        message = EventMessageFormatter.format_rds_instance_created(event)

        assert "my-database" in message
        assert "db.t3.medium" in message
        assert "postgres" in message
        assert "PUBLICLY ACCESSIBLE" in message or "PUBLIC" in message
        assert "False" in message or "encrypted" in message.lower()

    def test_format_rds_instance_created_private(self):
        """Test formatting CreateDBInstance for private instance."""
        event = {
            "requestParameters": {
                "dBInstanceIdentifier": "private-db",
                "dBInstanceClass": "db.r5.large",
                "engine": "mysql",
                "publiclyAccessible": False,
                "storageEncrypted": True,
            }
        }

        message = EventMessageFormatter.format_rds_instance_created(event)

        assert "private-db" in message
        assert "encrypted" in message.lower() or "True" in message

    def test_format_rds_instance_modified(self):
        """Test formatting ModifyDBInstance event."""
        event = {
            "requestParameters": {
                "dBInstanceIdentifier": "my-database",
                "publiclyAccessible": True,
                "masterUserPassword": "****",
            }
        }

        message = EventMessageFormatter.format_rds_instance_modified(event)

        assert "my-database" in message
        assert "public" in message.lower() or "Public" in message
        assert "password" in message.lower() or "Password" in message

    def test_format_rds_snapshot_shared(self):
        """Test formatting ModifyDBSnapshotAttribute event."""
        event = {
            "requestParameters": {
                "dBSnapshotIdentifier": "snapshot-123",
                "attributeName": "restore",
                "valuesToAdd": ["all"],
            }
        }

        message = EventMessageFormatter.format_rds_snapshot_shared(event)

        assert "snapshot-123" in message
        assert "PUBLIC" in message or "public" in message

    def test_format_s3_bucket_created(self):
        """Test formatting CreateBucket event."""
        event = {
            "requestParameters": {
                "bucketName": "my-bucket",
                "CreateBucketConfiguration": {"LocationConstraint": "us-west-2"},
            }
        }

        message = EventMessageFormatter.format_s3_bucket_created(event)

        assert "my-bucket" in message
        assert "region" in message.lower() or "us-west-2" in message

    def test_format_s3_bucket_policy_changed_public(self):
        """Test formatting PutBucketPolicy event with public policy."""
        event = {
            "requestParameters": {
                "bucketName": "public-bucket",
                "bucketPolicy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::public-bucket/*",
                        }
                    ]
                },
            }
        }

        message = EventMessageFormatter.format_s3_bucket_policy_changed(event)

        assert "public-bucket" in message
        assert "PUBLIC" in message or "public" in message

    def test_format_s3_public_access_block_changed_disabled(self):
        """Test formatting PutPublicAccessBlock with block disabled."""
        event = {
            "requestParameters": {
                "bucketName": "my-bucket",
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            }
        }

        message = EventMessageFormatter.format_s3_public_access_block_changed(event)

        assert "my-bucket" in message
        assert "DISABLED" in message or "disabled" in message

    def test_format_s3_encryption_changed(self):
        """Test formatting PutBucketEncryption event."""
        event = {
            "requestParameters": {
                "bucketName": "secure-bucket",
                "ServerSideEncryptionConfiguration": {
                    "rules": [
                        {
                            "applyServerSideEncryptionByDefault": {
                                "sSEAlgorithm": "AES256"
                            }
                        }
                    ]
                },
            }
        }

        message = EventMessageFormatter.format_s3_encryption_changed(event)

        assert "secure-bucket" in message
        assert "encryption" in message.lower() or "AES256" in message

    def test_format_lambda_function_created(self):
        """Test formatting CreateFunction event."""
        event = {
            "requestParameters": {
                "functionName": "my-function",
                "runtime": "python3.11",
                "role": "arn:aws:iam::123456789012:role/lambda-role",
            }
        }

        message = EventMessageFormatter.format_lambda_function_created(event)

        assert "my-function" in message
        assert "python3.11" in message
        assert "lambda-role" in message

    def test_format_lambda_permission_added_public(self):
        """Test formatting AddPermission event with public principal."""
        event = {
            "requestParameters": {
                "functionName": "public-function",
                "principal": "*",
                "action": "lambda:InvokeFunction",
            }
        }

        message = EventMessageFormatter.format_lambda_permission_added(event)

        assert "public-function" in message
        assert "PUBLIC" in message or "public" in message
        assert "lambda:InvokeFunction" in message or "InvokeFunction" in message

    def test_format_lambda_function_url_created_no_auth(self):
        """Test formatting CreateFunctionUrlConfig with no auth."""
        event = {
            "requestParameters": {
                "functionName": "url-function",
                "authType": "NONE",
                "cors": {"allowOrigins": ["*"]},
            }
        }

        message = EventMessageFormatter.format_lambda_function_url_created(event)

        assert "url-function" in message
        assert "NO AUTH" in message or "NONE" in message or "no auth" in message.lower()

    def test_format_lambda_code_updated(self):
        """Test formatting UpdateFunctionCode event."""
        event = {
            "requestParameters": {
                "functionName": "updated-function",
                "s3Bucket": "code-bucket",
                "s3Key": "function.zip",
            }
        }

        message = EventMessageFormatter.format_lambda_code_updated(event)

        assert "updated-function" in message
        assert "s3://code-bucket/function.zip" in message

    def test_format_subnet_modified_public_ip(self):
        """Test formatting ModifySubnetAttribute with auto-assign public IP."""
        event = {
            "requestParameters": {
                "subnetId": "subnet-123abc",
                "mapPublicIpOnLaunch": {"value": True},
            }
        }

        message = EventMessageFormatter.format_subnet_modified(event)

        assert "subnet-123abc" in message
        assert "AUTO-ASSIGN PUBLIC IP" in message or "public" in message.lower()

    def test_format_route_created_public(self):
        """Test formatting CreateRoute with internet gateway."""
        event = {
            "requestParameters": {
                "routeTableId": "rtb-123abc",
                "destinationCidrBlock": "0.0.0.0/0",
                "gatewayId": "igw-456def",
            }
        }

        message = EventMessageFormatter.format_route_created(event)

        assert "0.0.0.0/0" in message
        assert "igw-456def" in message
        assert "PUBLIC ROUTE" in message or "public" in message.lower()

    def test_format_internet_gateway_attached(self):
        """Test formatting AttachInternetGateway."""
        event = {
            "requestParameters": {
                "internetGatewayId": "igw-123abc",
                "vpcId": "vpc-456def",
            }
        }

        message = EventMessageFormatter.format_internet_gateway_attached(event)

        assert "igw-123abc" in message
        assert "vpc-456def" in message

    def test_format_elbv2_load_balancer_created_internet_facing(self):
        """Test formatting CreateLoadBalancer for internet-facing ALB."""
        event = {
            "requestParameters": {
                "name": "my-alb",
                "type": "application",
                "scheme": "internet-facing",
            }
        }

        message = EventMessageFormatter.format_elbv2_load_balancer_created(event)

        assert "my-alb" in message
        assert "application" in message
        assert "INTERNET-FACING" in message or "internet" in message.lower()

    def test_format_elbv2_listener_created_http(self):
        """Test formatting CreateListener with HTTP protocol."""
        event = {
            "requestParameters": {
                "protocol": "HTTP",
                "port": 80,
                "defaultActions": [],
            }
        }

        message = EventMessageFormatter.format_elbv2_listener_created(event)

        assert "HTTP" in message
        assert "80" in message
        assert "UNENCRYPTED" in message or "unencrypted" in message.lower()

    def test_format_iam_role_created_with_service(self):
        """Test formatting CreateRole with service principal."""
        import json

        assume_role_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": ["lambda.amazonaws.com", "ec2.amazonaws.com"]
                        },
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        )

        event = {
            "requestParameters": {
                "roleName": "MyLambdaRole",
                "assumeRolePolicyDocument": assume_role_policy,
            }
        }

        message = EventMessageFormatter.format_iam_role_created(event)

        assert "MyLambdaRole" in message
        assert "lambda.amazonaws.com" in message or "trusted by" in message.lower()

    def test_format_iam_policy_attached_privileged(self):
        """Test formatting AttachRolePolicy with admin policy."""
        event = {
            "requestParameters": {
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "roleName": "MyAdminRole",
            }
        }

        message = EventMessageFormatter.format_iam_policy_attached(event)

        assert "AdministratorAccess" in message
        assert "MyAdminRole" in message
        assert "PRIVILEGED" in message or "privileged" in message.lower()

    def test_format_iam_access_key_created(self):
        """Test formatting CreateAccessKey."""
        event = {
            "requestParameters": {"userName": "bob"},
            "responseElements": {"accessKey": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE"}},
        }

        message = EventMessageFormatter.format_iam_access_key_created(event)

        assert "AKIAIOSFODNN7EXAMPLE" in message
        assert "bob" in message

    def test_format_dynamodb_table_created_unencrypted(self):
        """Test formatting CreateTable without encryption."""
        event = {
            "requestParameters": {
                "tableName": "MyTable",
                "sSESpecification": {"enabled": False},
            }
        }

        message = EventMessageFormatter.format_dynamodb_table_created(event)

        assert "MyTable" in message
        assert "ENCRYPTION NOT ENABLED" in message or "encryption" in message.lower()

    def test_format_dynamodb_pitr_enabled(self):
        """Test formatting UpdateContinuousBackups with PITR enabled."""
        event = {
            "requestParameters": {
                "tableName": "MyTable",
                "pointInTimeRecoverySpecification": {
                    "pointInTimeRecoveryEnabled": True
                },
            }
        }

        message = EventMessageFormatter.format_dynamodb_pitr_updated(event)

        assert "MyTable" in message
        assert "PITR enabled" in message or "enabled" in message.lower()

    def test_format_kms_key_created_with_description(self):
        """Test formatting CreateKey event with description."""
        event = {
            "requestParameters": {
                "keySpec": "SYMMETRIC_DEFAULT",
                "keyUsage": "ENCRYPT_DECRYPT",
                "description": "My encryption key",
                "multiRegion": False,
            },
            "responseElements": {
                "keyMetadata": {"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab"}
            },
        }

        message = EventMessageFormatter.format_kms_key_created(event)

        assert "1234abcd-12ab-34cd-56ef-1234567890ab" in message
        assert "ENCRYPT_DECRYPT" in message
        assert "My encryption key" in message

    def test_format_kms_key_created_multi_region(self):
        """Test formatting CreateKey for multi-region key."""
        event = {
            "requestParameters": {
                "keySpec": "SYMMETRIC_DEFAULT",
                "keyUsage": "ENCRYPT_DECRYPT",
                "multiRegion": True,
            },
            "responseElements": {"keyMetadata": {"keyId": "mrk-1234abcd"}},
        }

        message = EventMessageFormatter.format_kms_key_created(event)

        assert "mrk-1234abcd" in message
        assert "Multi-region" in message

    def test_format_kms_key_deletion_scheduled(self):
        """Test formatting ScheduleKeyDeletion event."""
        event = {
            "requestParameters": {
                "keyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
                "pendingWindowInDays": 30,
            }
        }

        message = EventMessageFormatter.format_kms_key_deletion_scheduled(event)

        assert "1234abcd-12ab-34cd-56ef-1234567890ab" in message
        assert "30" in message
        assert "⚠️" in message or "DELETION SCHEDULED" in message

    def test_format_kms_key_deletion_scheduled_short_window(self):
        """Test formatting ScheduleKeyDeletion with minimum pending period."""
        event = {"requestParameters": {"keyId": "key-123", "pendingWindowInDays": 7}}

        message = EventMessageFormatter.format_kms_key_deletion_scheduled(event)

        assert "7 days" in message

    def test_format_kms_key_deletion_cancelled(self):
        """Test formatting CancelKeyDeletion event."""
        event = {"requestParameters": {"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab"}}

        message = EventMessageFormatter.format_kms_key_deletion_cancelled(event)

        assert "1234abcd-12ab-34cd-56ef-1234567890ab" in message
        assert "deletion cancelled" in message.lower() or "cancelled" in message.lower()

    def test_format_kms_key_disabled(self):
        """Test formatting DisableKey event."""
        event = {"requestParameters": {"keyId": "disabled-key-123"}}

        message = EventMessageFormatter.format_kms_key_disabled(event)

        assert "disabled-key-123" in message
        assert "⚠️" in message or "DISABLED" in message

    def test_format_kms_key_enabled(self):
        """Test formatting EnableKey event."""
        event = {"requestParameters": {"keyId": "enabled-key-456"}}

        message = EventMessageFormatter.format_kms_key_enabled(event)

        assert "enabled-key-456" in message
        assert "enabled" in message.lower()

    def test_format_kms_key_rotation_enabled(self):
        """Test formatting EnableKeyRotation event."""
        event = {"requestParameters": {"keyId": "rotation-key-789"}}

        message = EventMessageFormatter.format_kms_key_rotation_enabled(event)

        assert "rotation-key-789" in message
        assert "rotation enabled" in message.lower() or "ENABLED" in message

    def test_format_kms_key_rotation_disabled(self):
        """Test formatting DisableKeyRotation event."""
        event = {"requestParameters": {"keyId": "no-rotation-key"}}

        message = EventMessageFormatter.format_kms_key_rotation_disabled(event)

        assert "no-rotation-key" in message
        assert "⚠️" in message or "ROTATION DISABLED" in message

    def test_format_kms_key_policy_changed_public(self):
        """Test formatting PutKeyPolicy with public access policy."""
        import json

        public_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Allow public access",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    }
                ],
            }
        )

        event = {
            "requestParameters": {"keyId": "public-key-123", "policy": public_policy}
        }

        message = EventMessageFormatter.format_kms_key_policy_changed(event)

        assert "public-key-123" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    def test_format_kms_key_policy_changed_aws_principal_wildcard(self):
        """Test formatting PutKeyPolicy with AWS principal wildcard."""
        import json

        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Allow all AWS accounts",
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "kms:Encrypt",
                        "Resource": "*",
                    }
                ],
            }
        )

        event = {"requestParameters": {"keyId": "wildcard-key", "policy": policy}}

        message = EventMessageFormatter.format_kms_key_policy_changed(event)

        assert "wildcard-key" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    def test_format_kms_key_policy_changed_normal(self):
        """Test formatting PutKeyPolicy with restricted policy."""
        import json

        restricted_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Allow specific account",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )

        event = {
            "requestParameters": {
                "keyId": "restricted-key",
                "policy": restricted_policy,
            }
        }

        message = EventMessageFormatter.format_kms_key_policy_changed(event)

        assert "restricted-key" in message
        assert "policy changed" in message.lower()

    def test_format_kms_key_imported(self):
        """Test formatting ImportKeyMaterial event."""
        event = {
            "requestParameters": {
                "keyId": "imported-key-123",
                "importToken": "TOKEN123",
                "expirationModel": "KEY_MATERIAL_EXPIRES",
                "validTo": "2025-12-31T23:59:59Z",
            }
        }

        message = EventMessageFormatter.format_kms_key_imported(event)

        assert "imported-key-123" in message
        assert "imported" in message.lower() or "IMPORTED" in message

    def test_format_kms_grant_created(self):
        """Test formatting CreateGrant event."""
        event = {
            "requestParameters": {
                "keyId": "grant-key-123",
                "granteePrincipal": "arn:aws:iam::123456789012:role/MyRole",
                "operations": ["Decrypt", "DescribeKey"],
            },
            "responseElements": {"grantId": "grant-abc123"},
        }

        message = EventMessageFormatter.format_kms_grant_created(event)

        assert "grant-key-123" in message
        assert "MyRole" in message or "arn:aws:iam::123456789012:role/MyRole" in message
        assert "Decrypt" in message or "DescribeKey" in message

    def test_format_kms_grant_created_sensitive_operations(self):
        """Test formatting CreateGrant with sensitive operations."""
        event = {
            "requestParameters": {
                "keyId": "sensitive-key",
                "granteePrincipal": "arn:aws:iam::123456789012:role/ExternalRole",
                "operations": ["Decrypt", "CreateGrant"],
            },
            "responseElements": {"grantId": "grant-xyz789"},
        }

        message = EventMessageFormatter.format_kms_grant_created(event)

        assert "sensitive-key" in message
        assert "CreateGrant" in message or "Decrypt" in message

    def test_format_kms_grant_revoked(self):
        """Test formatting RevokeGrant event."""
        event = {
            "requestParameters": {
                "keyId": "revoke-key-123",
                "grantId": "grant-revoked-456",
            }
        }

        message = EventMessageFormatter.format_kms_grant_revoked(event)

        assert "revoke-key-123" in message
        assert "grant-revoked-456" in message
        assert "revoked" in message.lower() or "REVOKED" in message

    def test_format_cloudtrail_trail_created(self):
        """Test formatting CreateTrail event."""
        event = {
            "requestParameters": {
                "name": "my-trail",
                "s3BucketName": "my-cloudtrail-bucket",
                "isMultiRegionTrail": True,
                "enableLogFileValidation": True,
            }
        }

        message = EventMessageFormatter.format_cloudtrail_trail_created(event)

        assert "my-trail" in message
        assert "my-cloudtrail-bucket" in message
        assert "Multi-region" in message

    def test_format_cloudtrail_trail_created_no_validation(self):
        """Test formatting CreateTrail without log file validation."""
        event = {
            "requestParameters": {
                "name": "insecure-trail",
                "s3BucketName": "bucket",
                "enableLogFileValidation": False,
            }
        }

        message = EventMessageFormatter.format_cloudtrail_trail_created(event)

        assert "insecure-trail" in message
        assert "⚠️" in message or "LOG FILE VALIDATION DISABLED" in message

    def test_format_cloudtrail_trail_deleted(self):
        """Test formatting DeleteTrail event."""
        event = {"requestParameters": {"name": "deleted-trail"}}

        message = EventMessageFormatter.format_cloudtrail_trail_deleted(event)

        assert "deleted-trail" in message
        assert "⚠️" in message or "DELETED" in message

    def test_format_cloudtrail_logging_stopped(self):
        """Test formatting StopLogging event."""
        event = {"requestParameters": {"name": "stopped-trail"}}

        message = EventMessageFormatter.format_cloudtrail_logging_stopped(event)

        assert "stopped-trail" in message
        assert "⚠️" in message or "LOGGING STOPPED" in message

    def test_format_cloudtrail_event_selectors_updated_management_disabled(self):
        """Test formatting PutEventSelectors with management events disabled."""
        event = {
            "requestParameters": {
                "trailName": "my-trail",
                "eventSelectors": [{"IncludeManagementEvents": False}],
            }
        }

        message = EventMessageFormatter.format_cloudtrail_event_selectors_updated(event)

        assert "my-trail" in message
        assert "⚠️" in message or "MANAGEMENT EVENTS DISABLED" in message

    def test_format_ebs_volume_created_unencrypted(self):
        """Test formatting CreateVolume without encryption."""
        event = {
            "requestParameters": {
                "volumeId": "vol-123abc",
                "size": 100,
                "volumeType": "gp3",
                "encrypted": False,
                "availabilityZone": "us-east-1a",
            }
        }

        message = EventMessageFormatter.format_ebs_volume_created(event)

        assert "vol-123abc" in message
        assert "100GB" in message
        assert "gp3" in message
        assert "⚠️" in message or "ENCRYPTION NOT ENABLED" in message

    def test_format_ebs_volume_created_encrypted(self):
        """Test formatting CreateVolume with encryption."""
        event = {
            "requestParameters": {
                "volumeId": "vol-encrypted",
                "size": 50,
                "volumeType": "gp2",
                "encrypted": True,
                "availabilityZone": "us-west-2b",
            }
        }

        message = EventMessageFormatter.format_ebs_volume_created(event)

        assert "vol-encrypted" in message
        assert "50GB" in message
        assert "ENCRYPTION NOT ENABLED" not in message

    def test_format_ebs_volume_modified(self):
        """Test formatting ModifyVolume event."""
        event = {
            "requestParameters": {
                "volumeId": "vol-modified",
                "size": 200,
                "volumeType": "io2",
                "iops": 10000,
            }
        }

        message = EventMessageFormatter.format_ebs_volume_modified(event)

        assert "vol-modified" in message
        assert "200GB" in message or "io2" in message or "10000" in message

    def test_format_ebs_snapshot_shared_public(self):
        """Test formatting ModifySnapshotAttribute making snapshot public."""
        event = {
            "requestParameters": {
                "snapshotId": "snap-public-123",
                "createVolumePermission": {"add": {"items": [{"group": "all"}]}},
            }
        }

        message = EventMessageFormatter.format_ebs_snapshot_shared(event)

        assert "snap-public-123" in message
        assert "⚠️" in message or "PUBLIC" in message

    def test_format_ebs_snapshot_shared_specific_account(self):
        """Test formatting ModifySnapshotAttribute sharing with specific account."""
        event = {
            "requestParameters": {
                "snapshotId": "snap-shared",
                "createVolumePermission": {
                    "add": {
                        "items": [
                            {"userId": "123456789012"},
                            {"userId": "210987654321"},
                        ]
                    }
                },
            }
        }

        message = EventMessageFormatter.format_ebs_snapshot_shared(event)

        assert "snap-shared" in message
        assert "2 account(s)" in message or "shared" in message.lower()

    def test_format_ebs_encryption_disabled(self):
        """Test formatting DisableEbsEncryptionByDefault event."""
        message = EventMessageFormatter.format_ebs_encryption_disabled({})

        assert "⚠️" in message or "DISABLED" in message
        assert "encryption" in message.lower() or "EBS" in message

    def test_format_secrets_manager_secret_created_no_custom_key(self):
        """Test formatting CreateSecret without custom KMS key."""
        event = {
            "requestParameters": {
                "name": "my-secret",
                "description": "Database credentials",
            },
            "responseElements": {
                "aRN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret"
            },
        }

        message = EventMessageFormatter.format_secrets_manager_secret_created(event)

        assert "my-secret" in message
        assert "Database credentials" in message
        assert "⚠️" in message or "DEFAULT ENCRYPTION KEY" in message

    def test_format_secrets_manager_secret_created_with_custom_key(self):
        """Test formatting CreateSecret with custom KMS key."""
        event = {
            "requestParameters": {
                "name": "secure-secret",
                "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
            },
            "responseElements": {},
        }

        message = EventMessageFormatter.format_secrets_manager_secret_created(event)

        assert "secure-secret" in message
        assert "DEFAULT ENCRYPTION KEY" not in message

    def test_format_secrets_manager_secret_deleted_force(self):
        """Test formatting DeleteSecret with force delete."""
        event = {
            "requestParameters": {
                "secretId": "permanent-delete",
                "forceDeleteWithoutRecovery": True,
            }
        }

        message = EventMessageFormatter.format_secrets_manager_secret_deleted(event)

        assert "permanent-delete" in message
        assert (
            "⚠️" in message
            or "PERMANENTLY DELETED" in message
            or "NO RECOVERY" in message
        )

    def test_format_secrets_manager_secret_deleted_with_recovery(self):
        """Test formatting DeleteSecret with recovery window."""
        event = {
            "requestParameters": {
                "secretId": "recoverable-secret",
                "recoveryWindowInDays": 7,
            }
        }

        message = EventMessageFormatter.format_secrets_manager_secret_deleted(event)

        assert "recoverable-secret" in message
        assert "7 days" in message or "recovery window" in message.lower()

    def test_format_secrets_manager_rotation_enabled(self):
        """Test formatting RotateSecret when enabling rotation."""
        event = {
            "requestParameters": {
                "secretId": "rotated-secret",
                "rotationRules": {"automaticallyAfterDays": 30},
                "rotationLambdaARN": "arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRotation",
            }
        }

        message = EventMessageFormatter.format_secrets_manager_rotation_enabled(event)

        assert "rotated-secret" in message
        assert "30 days" in message or "30" in message
        assert "SecretsManagerRotation" in message or "Lambda" in message

    def test_format_secrets_manager_rotation_disabled(self):
        """Test formatting CancelRotateSecret event."""
        event = {"requestParameters": {"secretId": "no-rotation-secret"}}

        message = EventMessageFormatter.format_secrets_manager_rotation_disabled(event)

        assert "no-rotation-secret" in message
        assert "⚠️" in message or "ROTATION DISABLED" in message

    def test_format_secrets_manager_policy_changed_public(self):
        """Test formatting PutResourcePolicy with public access."""
        import json

        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    }
                ],
            }
        )

        event = {
            "requestParameters": {"secretId": "public-secret", "resourcePolicy": policy}
        }

        message = EventMessageFormatter.format_secrets_manager_policy_changed(event)

        assert "public-secret" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    def test_format_cloudwatch_alarm_created(self):
        """Test formatting PutMetricAlarm event."""
        event = {
            "requestParameters": {
                "alarmName": "HighCPUAlarm",
                "metricName": "CPUUtilization",
                "namespace": "AWS/EC2",
                "comparisonOperator": "GreaterThanThreshold",
                "threshold": 80,
                "actionsEnabled": True,
            }
        }

        message = EventMessageFormatter.format_cloudwatch_alarm_created(event)

        assert "HighCPUAlarm" in message
        assert "AWS/EC2/CPUUtilization" in message or "CPUUtilization" in message
        assert "80" in message

    def test_format_cloudwatch_alarm_created_actions_disabled(self):
        """Test formatting PutMetricAlarm with actions disabled."""
        event = {
            "requestParameters": {"alarmName": "DisabledAlarm", "actionsEnabled": False}
        }

        message = EventMessageFormatter.format_cloudwatch_alarm_created(event)

        assert "DisabledAlarm" in message
        assert "⚠️" in message or "ACTIONS DISABLED" in message

    def test_format_cloudwatch_alarm_deleted_single(self):
        """Test formatting DeleteAlarms for single alarm."""
        event = {"requestParameters": {"alarmNames": ["MyAlarm"]}}

        message = EventMessageFormatter.format_cloudwatch_alarm_deleted(event)

        assert "MyAlarm" in message
        assert "deleted" in message.lower()

    def test_format_cloudwatch_alarm_deleted_multiple(self):
        """Test formatting DeleteAlarms for multiple alarms."""
        event = {
            "requestParameters": {
                "alarmNames": ["Alarm1", "Alarm2", "Alarm3", "Alarm4", "Alarm5"]
            }
        }

        message = EventMessageFormatter.format_cloudwatch_alarm_deleted(event)

        assert "5 alarms" in message or "deleted" in message.lower()
        assert "⚠️" in message or "alarms deleted" in message.lower()

    def test_format_cloudwatch_alarm_actions_disabled(self):
        """Test formatting DisableAlarmActions event."""
        event = {"requestParameters": {"alarmNames": ["CriticalAlarm"]}}

        message = EventMessageFormatter.format_cloudwatch_alarm_actions_disabled(event)

        assert "CriticalAlarm" in message
        assert "⚠️" in message or "ACTIONS DISABLED" in message

    def test_format_cloudwatch_alarm_actions_disabled_multiple(self):
        """Test formatting DisableAlarmActions for multiple alarms."""
        event = {"requestParameters": {"alarmNames": ["Alarm1", "Alarm2", "Alarm3"]}}

        message = EventMessageFormatter.format_cloudwatch_alarm_actions_disabled(event)

        assert "3 alarms" in message or "DISABLED" in message
        assert "⚠️" in message

    def test_format_cloudwatch_alarm_state_changed(self):
        """Test formatting SetAlarmState event."""
        event = {
            "requestParameters": {
                "alarmName": "MyAlarm",
                "stateValue": "ALARM",
                "stateReason": "Threshold crossed",
            }
        }

        message = EventMessageFormatter.format_cloudwatch_alarm_state_changed(event)

        assert "MyAlarm" in message
        assert "ALARM" in message
        assert "Threshold crossed" in message

    def test_format_cloudwatch_log_group_created(self):
        """Test formatting CreateLogGroup event."""
        event = {"requestParameters": {"logGroupName": "/aws/lambda/my-function"}}

        message = EventMessageFormatter.format_cloudwatch_log_group_created(event)

        assert "/aws/lambda/my-function" in message
        assert "created" in message.lower()

    def test_format_cloudwatch_log_group_deleted(self):
        """Test formatting DeleteLogGroup event."""
        event = {"requestParameters": {"logGroupName": "/aws/lambda/old-function"}}

        message = EventMessageFormatter.format_cloudwatch_log_group_deleted(event)

        assert "/aws/lambda/old-function" in message
        assert "deleted" in message.lower()

    def test_format_cloudwatch_log_retention_changed_short(self):
        """Test formatting PutRetentionPolicy with short retention."""
        event = {
            "requestParameters": {
                "logGroupName": "/aws/lambda/test",
                "retentionInDays": 3,
            }
        }

        message = EventMessageFormatter.format_cloudwatch_log_retention_changed(event)

        assert "/aws/lambda/test" in message
        assert "3 days" in message
        assert "⚠️" in message or "SHORT RETENTION" in message

    def test_format_cloudwatch_log_retention_changed_normal(self):
        """Test formatting PutRetentionPolicy with normal retention."""
        event = {
            "requestParameters": {
                "logGroupName": "/aws/lambda/prod",
                "retentionInDays": 30,
            }
        }

        message = EventMessageFormatter.format_cloudwatch_log_retention_changed(event)

        assert "/aws/lambda/prod" in message
        assert "30 days" in message
        assert "SHORT RETENTION" not in message

    # ========== SNS Formatter Tests ==========

    def test_format_sns_topic_created(self):
        """Test formatting CreateTopic event."""
        event = {
            "requestParameters": {"name": "notifications"},
            "responseElements": {
                "topicArn": "arn:aws:sns:us-east-1:123456789012:notifications"
            },
        }

        message = EventMessageFormatter.format_sns_topic_created(event)

        assert "notifications" in message
        assert "arn:aws:sns:us-east-1:123456789012:notifications" in message

    def test_format_sns_topic_deleted(self):
        """Test formatting DeleteTopic event."""
        event = {
            "requestParameters": {
                "topicArn": "arn:aws:sns:us-east-1:123456789012:old-topic"
            }
        }

        message = EventMessageFormatter.format_sns_topic_deleted(event)

        assert "old-topic" in message

    def test_format_sns_topic_attribute_changed_public_policy(self):
        """Test formatting SetTopicAttributes with public policy."""
        event = {
            "requestParameters": {
                "topicArn": "arn:aws:sns:us-east-1:123456789012:public-topic",
                "attributeName": "Policy",
                "attributeValue": '{"Statement":[{"Principal":"*","Action":"SNS:Subscribe"}]}',
            }
        }

        message = EventMessageFormatter.format_sns_topic_attribute_changed(event)

        assert "public-topic" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    def test_format_sns_subscription_created_http(self):
        """Test formatting Subscribe event with HTTP protocol."""
        event = {
            "requestParameters": {
                "topicArn": "arn:aws:sns:us-east-1:123456789012:alerts",
                "protocol": "http",
                "endpoint": "http://example.com/webhook",
            }
        }

        message = EventMessageFormatter.format_sns_subscription_created(event)

        assert "alerts" in message
        assert "http" in message
        assert "⚠️" in message or "UNENCRYPTED" in message

    def test_format_sns_subscription_created_https(self):
        """Test formatting Subscribe event with HTTPS protocol."""
        event = {
            "requestParameters": {
                "topicArn": "arn:aws:sns:us-east-1:123456789012:alerts",
                "protocol": "https",
                "endpoint": "https://example.com/webhook",
            }
        }

        message = EventMessageFormatter.format_sns_subscription_created(event)

        assert "alerts" in message
        assert "https" in message
        assert "UNENCRYPTED" not in message

    def test_format_sns_subscription_deleted(self):
        """Test formatting Unsubscribe event."""
        event = {
            "requestParameters": {
                "subscriptionArn": "arn:aws:sns:us-east-1:123456789012:alerts:sub-id"
            }
        }

        message = EventMessageFormatter.format_sns_subscription_deleted(event)

        assert "sub-id" in message

    # ========== SQS Formatter Tests ==========

    def test_format_sqs_queue_created_encrypted(self):
        """Test formatting CreateQueue event with encryption."""
        event = {
            "requestParameters": {
                "queueName": "secure-queue",
                "attributes": {"KmsMasterKeyId": "alias/aws/sqs"},
            },
            "responseElements": {
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/secure-queue"
            },
        }

        message = EventMessageFormatter.format_sqs_queue_created(event)

        assert "secure-queue" in message
        assert "ENCRYPTION NOT ENABLED" not in message

    def test_format_sqs_queue_created_unencrypted(self):
        """Test formatting CreateQueue event without encryption."""
        event = {
            "requestParameters": {"queueName": "insecure-queue", "attributes": {}},
            "responseElements": {
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/insecure-queue"
            },
        }

        message = EventMessageFormatter.format_sqs_queue_created(event)

        assert "insecure-queue" in message
        assert "⚠️" in message or "ENCRYPTION NOT ENABLED" in message

    def test_format_sqs_queue_deleted(self):
        """Test formatting DeleteQueue event."""
        event = {
            "requestParameters": {
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/old-queue"
            }
        }

        message = EventMessageFormatter.format_sqs_queue_deleted(event)

        assert "old-queue" in message

    def test_format_sqs_queue_attribute_changed_encryption_disabled(self):
        """Test formatting SetQueueAttributes with encryption disabled."""
        event = {
            "requestParameters": {
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
                "attributes": {"KmsMasterKeyId": ""},
            }
        }

        message = EventMessageFormatter.format_sqs_queue_attribute_changed(event)

        assert "my-queue" in message
        assert "⚠️" in message or "ENCRYPTION DISABLED" in message

    def test_format_sqs_queue_policy_changed_public(self):
        """Test formatting SetQueueAttributes with public policy."""
        event = {
            "requestParameters": {
                "queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/public-queue",
                "attributes": {
                    "Policy": '{"Statement":[{"Principal":"*","Action":"SQS:SendMessage"}]}'
                },
            }
        }

        message = EventMessageFormatter.format_sqs_queue_policy_changed(event)

        assert "public-queue" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    # ========== ECR Formatter Tests ==========

    def test_format_ecr_repository_created_encrypted(self):
        """Test formatting CreateRepository event with encryption."""
        event = {
            "requestParameters": {
                "repositoryName": "my-app",
                "encryptionConfiguration": {
                    "encryptionType": "KMS",
                    "kmsKey": "alias/ecr-key",
                },
            },
            "responseElements": {
                "repository": {
                    "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app"
                }
            },
        }

        message = EventMessageFormatter.format_ecr_repository_created(event)

        assert "my-app" in message
        assert "KMS" in message
        assert "ENCRYPTION NOT CONFIGURED" not in message

    def test_format_ecr_repository_created_unencrypted(self):
        """Test formatting CreateRepository event without encryption."""
        event = {
            "requestParameters": {"repositoryName": "insecure-app"},
            "responseElements": {"repository": {}},
        }

        message = EventMessageFormatter.format_ecr_repository_created(event)

        assert "insecure-app" in message
        assert "⚠️" in message or "ENCRYPTION NOT CONFIGURED" in message

    def test_format_ecr_repository_deleted(self):
        """Test formatting DeleteRepository event."""
        event = {"requestParameters": {"repositoryName": "old-app", "force": True}}

        message = EventMessageFormatter.format_ecr_repository_deleted(event)

        assert "old-app" in message
        assert "forced" in message

    def test_format_ecr_image_pushed(self):
        """Test formatting PutImage event."""
        event = {
            "requestParameters": {"repositoryName": "my-app", "imageTag": "v1.0.0"},
            "responseElements": {"image": {}},
        }

        message = EventMessageFormatter.format_ecr_image_pushed(event)

        assert "my-app" in message
        assert "v1.0.0" in message

    def test_format_ecr_image_deleted(self):
        """Test formatting BatchDeleteImage event."""
        event = {
            "requestParameters": {
                "repositoryName": "my-app",
                "imageIds": [{"imageTag": "v1.0.0"}, {"imageTag": "v1.0.1"}],
            }
        }

        message = EventMessageFormatter.format_ecr_image_deleted(event)

        assert "my-app" in message
        assert "2" in message

    def test_format_ecr_repository_policy_set_public(self):
        """Test formatting SetRepositoryPolicy with public policy."""
        event = {
            "requestParameters": {
                "repositoryName": "public-repo",
                "policyText": '{"Statement":[{"Principal":"*","Action":"ecr:GetDownloadUrlForLayer"}]}',
            }
        }

        message = EventMessageFormatter.format_ecr_repository_policy_set(event)

        assert "public-repo" in message
        assert "⚠️" in message or "PUBLIC ACCESS" in message

    def test_format_ecr_image_scan_configured_enabled(self):
        """Test formatting PutImageScanningConfiguration with scan enabled."""
        event = {
            "requestParameters": {
                "repositoryName": "my-app",
                "imageScanningConfiguration": {"scanOnPush": True},
            }
        }

        message = EventMessageFormatter.format_ecr_image_scan_configured(event)

        assert "my-app" in message
        assert "ENABLED" in message
        assert "⚠️" not in message

    def test_format_ecr_image_scan_configured_disabled(self):
        """Test formatting PutImageScanningConfiguration with scan disabled."""
        event = {
            "requestParameters": {
                "repositoryName": "my-app",
                "imageScanningConfiguration": {"scanOnPush": False},
            }
        }

        message = EventMessageFormatter.format_ecr_image_scan_configured(event)

        assert "my-app" in message
        assert "⚠️" in message or "DISABLED" in message

    # ========== ECS Formatter Tests ==========

    def test_format_ecs_cluster_created(self):
        """Test formatting CreateCluster event."""
        event = {
            "requestParameters": {"clusterName": "production"},
            "responseElements": {
                "cluster": {
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/production"
                }
            },
        }

        message = EventMessageFormatter.format_ecs_cluster_created(event)

        assert "production" in message
        assert "cluster" in message

    def test_format_ecs_cluster_deleted(self):
        """Test formatting DeleteCluster event."""
        event = {"requestParameters": {"cluster": "old-cluster"}}

        message = EventMessageFormatter.format_ecs_cluster_deleted(event)

        assert "old-cluster" in message

    def test_format_ecs_service_created_with_public_ip(self):
        """Test formatting CreateService event with public IP."""
        event = {
            "requestParameters": {
                "serviceName": "web-service",
                "cluster": "production",
                "taskDefinition": "web:1",
                "desiredCount": 3,
                "launchType": "FARGATE",
                "networkConfiguration": {
                    "awsvpcConfiguration": {"assignPublicIp": "ENABLED"}
                },
            },
            "responseElements": {},
        }

        message = EventMessageFormatter.format_ecs_service_created(event)

        assert "web-service" in message
        assert "production" in message
        assert "⚠️" in message or "PUBLIC IP" in message

    def test_format_ecs_service_created_without_public_ip(self):
        """Test formatting CreateService event without public IP."""
        event = {
            "requestParameters": {
                "serviceName": "web-service",
                "cluster": "production",
                "taskDefinition": "web:1",
                "desiredCount": 3,
            },
            "responseElements": {},
        }

        message = EventMessageFormatter.format_ecs_service_created(event)

        assert "web-service" in message
        assert "production" in message
        assert "PUBLIC IP" not in message

    def test_format_ecs_service_deleted(self):
        """Test formatting DeleteService event."""
        event = {
            "requestParameters": {
                "service": "old-service",
                "cluster": "production",
                "force": True,
            }
        }

        message = EventMessageFormatter.format_ecs_service_deleted(event)

        assert "old-service" in message
        assert "production" in message
        assert "forced" in message

    def test_format_ecs_service_updated(self):
        """Test formatting UpdateService event."""
        event = {
            "requestParameters": {
                "service": "web-service",
                "cluster": "production",
                "desiredCount": 5,
                "taskDefinition": "web:2",
            }
        }

        message = EventMessageFormatter.format_ecs_service_updated(event)

        assert "web-service" in message
        assert "production" in message
        assert "5" in message

    def test_format_ecs_task_definition_registered_privileged(self):
        """Test formatting RegisterTaskDefinition event with privileged container."""
        event = {
            "requestParameters": {
                "family": "web",
                "networkMode": "awsvpc",
                "containerDefinitions": [{"name": "nginx", "privileged": True}],
            },
            "responseElements": {"taskDefinition": {"revision": "5"}},
        }

        message = EventMessageFormatter.format_ecs_task_definition_registered(event)

        assert "web" in message
        assert "5" in message
        assert "⚠️" in message or "PRIVILEGED" in message

    def test_format_ecs_task_definition_registered_normal(self):
        """Test formatting RegisterTaskDefinition event without privileged container."""
        event = {
            "requestParameters": {
                "family": "web",
                "networkMode": "awsvpc",
                "containerDefinitions": [{"name": "nginx", "privileged": False}],
            },
            "responseElements": {"taskDefinition": {"revision": "6"}},
        }

        message = EventMessageFormatter.format_ecs_task_definition_registered(event)

        assert "web" in message
        assert "6" in message
        assert "PRIVILEGED" not in message

    def test_format_ecs_task_definition_deregistered(self):
        """Test formatting DeregisterTaskDefinition event."""
        event = {"requestParameters": {"taskDefinition": "web:3"}}

        message = EventMessageFormatter.format_ecs_task_definition_deregistered(event)

        assert "web:3" in message
