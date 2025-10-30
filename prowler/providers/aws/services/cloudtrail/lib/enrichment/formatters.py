"""Event message formatters for CloudTrail events.

These formatters parse CloudTrail event JSON and create human-readable
messages describing what happened. Inspired by Luminaut's event formatting.
"""

from typing import Any

from prowler.lib.logger import logger


class EventMessageFormatter:
    """Formats CloudTrail events into human-readable messages."""

    @staticmethod
    def format_security_group_rule_added(event: dict[str, Any]) -> str:
        """Format AuthorizeSecurityGroupIngress event.

        Args:
            event: CloudTrail event dict containing requestParameters

        Returns:
            Human-readable description of the rule that was added
        """
        request_params = event.get("requestParameters", {})
        ip_perms = request_params.get("ipPermissions", {})
        rules = []

        # Handle both dict and list formats from CloudTrail
        items = ip_perms.get("items", []) if isinstance(ip_perms, dict) else ip_perms

        for perm in items:
            protocol = perm.get("ipProtocol", "unknown")
            from_port = perm.get("fromPort", "")
            to_port = perm.get("toPort", "")

            # Format port range
            if from_port == to_port:
                port_range = str(from_port)
            elif from_port and to_port:
                port_range = f"{from_port}-{to_port}"
            else:
                port_range = "all"

            # Handle IPv4 ranges
            ip_ranges = perm.get("ipRanges", {})
            ipv4_items = (
                ip_ranges.get("items", []) if isinstance(ip_ranges, dict) else ip_ranges
            )
            for ip_range in ipv4_items:
                cidr = ip_range.get("cidrIp", "unknown")
                rules.append(f"Allow {cidr}:{port_range} over {protocol}")

            # Handle IPv6 ranges
            ipv6_ranges = perm.get("ipv6Ranges", {})
            ipv6_items = (
                ipv6_ranges.get("items", [])
                if isinstance(ipv6_ranges, dict)
                else ipv6_ranges
            )
            for ip_range in ipv6_items:
                cidr = ip_range.get("cidrIpv6", "unknown")
                rules.append(f"Allow {cidr}:{port_range} over {protocol}")

            # Handle security group references
            groups = perm.get("groups", {})
            group_items = (
                groups.get("items", []) if isinstance(groups, dict) else groups
            )
            for group in group_items:
                group_id = group.get("groupId", "unknown")
                rules.append(f"Allow {group_id}:{port_range} over {protocol}")

        if rules:
            return "Ingress rule added: " + ", ".join(rules)
        return "Ingress rule added"

    @staticmethod
    def format_security_group_rule_modified(event: dict[str, Any]) -> str:
        """Format ModifySecurityGroupRules event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the rule modification
        """
        request_params = event.get("requestParameters", {})
        sg_rule_request = request_params.get("ModifySecurityGroupRulesRequest", {})
        sg_rule = sg_rule_request.get("SecurityGroupRule", {})

        if not sg_rule:
            return "Security group rules modified"

        from_port = sg_rule.get("FromPort")
        to_port = sg_rule.get("ToPort")
        protocol = sg_rule.get("IpProtocol", "unknown")

        if from_port == to_port:
            port_range = str(from_port) if from_port else "all"
        else:
            port_range = f"{from_port}-{to_port}" if from_port and to_port else "all"

        cidr_ipv4 = sg_rule.get("CidrIpv4")
        if cidr_ipv4:
            return f"Rule updated to: {cidr_ipv4}:{port_range} over {protocol}"

        return "Security group rules modified"

    @staticmethod
    def format_security_group_rule_removed(event: dict[str, Any]) -> str:
        """Format RevokeSecurityGroupIngress event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the rule that was removed
        """
        # Similar structure to format_security_group_rule_added
        message = EventMessageFormatter.format_security_group_rule_added(event)
        return message.replace("Ingress rule added:", "Ingress rule removed:")

    @staticmethod
    def format_instance_created(event: dict[str, Any]) -> str:
        """Format RunInstances event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the instance that was created
        """
        request_params = event.get("requestParameters", {})
        instance_type = request_params.get("instanceType", "unknown")
        ami_id = request_params.get("imageId", "unknown")

        message = f"Instance created (type: {instance_type}, AMI: {ami_id})"

        # Add security group context
        network_interfaces = request_params.get("networkInterfaceSet", {})
        ni_items = (
            network_interfaces.get("items", [])
            if isinstance(network_interfaces, dict)
            else network_interfaces
        )

        sg_ids = []
        for ni in ni_items:
            groups = ni.get("groupSet", {})
            group_items = (
                groups.get("items", []) if isinstance(groups, dict) else groups
            )
            for group in group_items:
                if group_id := group.get("groupId"):
                    sg_ids.append(group_id)

        if sg_ids:
            message += f" with security groups: {', '.join(sg_ids)}"

        return message

    @staticmethod
    def format_eni_attribute_modification(event: dict[str, Any]) -> str:
        """Format ModifyNetworkInterfaceAttribute event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the ENI attribute change
        """
        request_params = event.get("requestParameters", {})

        # Check for security group changes
        group_set = request_params.get("groupSet", {})
        if group_set:
            sg_items = (
                group_set.get("items", []) if isinstance(group_set, dict) else group_set
            )
            sg_ids = [sg.get("groupId") for sg in sg_items if sg.get("groupId")]

            if sg_ids:
                return f"Security groups updated: {', '.join(sg_ids)}"

        # Check for source/dest check changes
        if "sourceDestCheck" in request_params:
            value = request_params["sourceDestCheck"].get("value")
            return f"Source/destination check set to: {value}"

        # Check for description changes
        if "description" in request_params:
            return "Network interface description updated"

        return "Network interface attribute modified"

    @staticmethod
    def format_load_balancer_created(event: dict[str, Any]) -> str:
        """Format CreateLoadBalancer event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the load balancer creation
        """
        request_params = event.get("requestParameters", {})
        lb_name = request_params.get("name", "unknown")
        lb_type = request_params.get("type", "unknown")
        scheme = request_params.get("scheme", "unknown")

        return f"Load balancer created: {lb_name} (type: {lb_type}, scheme: {scheme})"

    @staticmethod
    def extract_principal_name(event: dict[str, Any]) -> str:
        """Extract a friendly principal name from CloudTrail event.

        Extracts the IAM user/role name from the full ARN or session info.

        Args:
            event: CloudTrail event dict

        Returns:
            Friendly principal name (e.g., "admin@company.com" or "deploy-role")
        """
        user_identity = event.get("userIdentity", {})

        # Try to get username/session name
        if principal_id := user_identity.get("principalId"):
            # For assumed roles, principalId is like "AIDAI....:user@example.com"
            if ":" in principal_id:
                return principal_id.split(":", 1)[1]

        # Try userName for IAM users
        if user_name := user_identity.get("userName"):
            return user_name

        # Try sessionContext for assumed roles
        if session_context := user_identity.get("sessionContext", {}).get(
            "sessionIssuer", {}
        ):
            if user_name := session_context.get("userName"):
                return user_name

        # Fall back to ARN
        if arn := user_identity.get("arn"):
            # Extract the name from ARN
            # Format: arn:aws:iam::123456789012:user/admin
            if "/" in arn:
                return arn.split("/")[-1]
            return arn

        # Last resort
        return user_identity.get("type", "unknown")

    # RDS Event Formatters

    @staticmethod
    def format_rds_instance_created(event: dict[str, Any]) -> str:
        """Format CreateDBInstance event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of the RDS instance creation
        """
        request_params = event.get("requestParameters", {})
        db_instance_id = request_params.get("dBInstanceIdentifier", "unknown")
        db_instance_class = request_params.get("dBInstanceClass", "unknown")
        engine = request_params.get("engine", "unknown")
        publicly_accessible = request_params.get("publiclyAccessible", False)

        message = f"RDS instance created: {db_instance_id} (class: {db_instance_class}, engine: {engine})"

        if publicly_accessible:
            message += " - ⚠️ PUBLICLY ACCESSIBLE"

        # Add encryption info
        if "storageEncrypted" in request_params:
            storage_encrypted = request_params.get("storageEncrypted")
            message += f", encrypted: {storage_encrypted}"

        return message

    @staticmethod
    def format_rds_instance_modified(event: dict[str, Any]) -> str:
        """Format ModifyDBInstance event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of RDS instance modifications
        """
        request_params = event.get("requestParameters", {})
        db_instance_id = request_params.get("dBInstanceIdentifier", "unknown")

        modifications = []

        if "publiclyAccessible" in request_params:
            publicly_accessible = request_params["publiclyAccessible"]
            status = "ENABLED" if publicly_accessible else "disabled"
            modifications.append(f"public access {status}")

        if "backupRetentionPeriod" in request_params:
            period = request_params["backupRetentionPeriod"]
            modifications.append(f"backup retention: {period} days")

        if "masterUserPassword" in request_params:
            modifications.append("master password changed")

        if (
            "dBSecurityGroups" in request_params
            or "vPCSecurityGroupIds" in request_params
        ):
            modifications.append("security groups updated")

        if modifications:
            return (
                f"RDS instance modified: {db_instance_id} - {', '.join(modifications)}"
            )

        return f"RDS instance modified: {db_instance_id}"

    @staticmethod
    def format_rds_snapshot_shared(event: dict[str, Any]) -> str:
        """Format ModifyDBSnapshotAttribute event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of snapshot sharing
        """
        request_params = event.get("requestParameters", {})
        snapshot_id = request_params.get("dBSnapshotIdentifier", "unknown")
        attribute_name = request_params.get("attributeName", "unknown")

        if attribute_name == "restore":
            values_to_add = request_params.get("valuesToAdd", [])

            # valuesToAdd can be a list or a dict with "items" key
            if isinstance(values_to_add, dict):
                values = values_to_add.get("items", [])
            else:
                values = values_to_add if isinstance(values_to_add, list) else []

            if "all" in values:
                return f"⚠️ RDS snapshot made PUBLIC: {snapshot_id}"
            elif values:
                return f"RDS snapshot shared with accounts: {snapshot_id} - {', '.join(values)}"

        return f"RDS snapshot attribute modified: {snapshot_id}"

    # S3 Event Formatters

    @staticmethod
    def format_s3_bucket_created(event: dict[str, Any]) -> str:
        """Format CreateBucket event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of bucket creation
        """
        request_params = event.get("requestParameters", {})
        bucket_name = request_params.get("bucketName", "unknown")

        message = f"S3 bucket created: {bucket_name}"

        # Add region if available
        if bucket_config := request_params.get("CreateBucketConfiguration", {}):
            if region := bucket_config.get("LocationConstraint"):
                message += f" in region {region}"

        return message

    @staticmethod
    def format_s3_bucket_policy_changed(event: dict[str, Any]) -> str:
        """Format PutBucketPolicy event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of bucket policy change
        """
        request_params = event.get("requestParameters", {})
        bucket_name = request_params.get("bucketName", "unknown")

        # Try to parse policy for public access
        bucket_policy = request_params.get("bucketPolicy", {})
        if isinstance(bucket_policy, str):
            import json

            try:
                policy_doc = json.loads(bucket_policy)
                # Check for public access in statements
                for statement in policy_doc.get("Statement", []):
                    principal = statement.get("Principal", {})
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        return f"⚠️ S3 bucket policy changed to ALLOW PUBLIC ACCESS: {bucket_name}"
            except (json.JSONDecodeError, AttributeError):
                pass

        return f"S3 bucket policy changed: {bucket_name}"

    @staticmethod
    def format_s3_public_access_block_changed(event: dict[str, Any]) -> str:
        """Format PutPublicAccessBlock event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of public access block change
        """
        request_params = event.get("requestParameters", {})
        bucket_name = request_params.get("bucketName", "unknown")
        public_access_block_config = request_params.get(
            "PublicAccessBlockConfiguration", {}
        )

        block_public_acls = public_access_block_config.get("BlockPublicAcls", True)
        ignore_public_acls = public_access_block_config.get("IgnorePublicAcls", True)
        block_public_policy = public_access_block_config.get("BlockPublicPolicy", True)
        restrict_public_buckets = public_access_block_config.get(
            "RestrictPublicBuckets", True
        )

        all_blocked = all(
            [
                block_public_acls,
                ignore_public_acls,
                block_public_policy,
                restrict_public_buckets,
            ]
        )

        if all_blocked:
            return f"S3 public access block ENABLED: {bucket_name}"
        else:
            disabled_features = []
            if not block_public_acls:
                disabled_features.append("BlockPublicAcls")
            if not ignore_public_acls:
                disabled_features.append("IgnorePublicAcls")
            if not block_public_policy:
                disabled_features.append("BlockPublicPolicy")
            if not restrict_public_buckets:
                disabled_features.append("RestrictPublicBuckets")

            return f"⚠️ S3 public access block DISABLED: {bucket_name} - {', '.join(disabled_features)}"

    @staticmethod
    def format_s3_encryption_changed(event: dict[str, Any]) -> str:
        """Format PutBucketEncryption event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of encryption configuration
        """
        request_params = event.get("requestParameters", {})
        bucket_name = request_params.get("bucketName", "unknown")

        encryption_config = request_params.get("ServerSideEncryptionConfiguration", {})
        rules = encryption_config.get("rules", {})
        rule_items = rules.get("items", []) if isinstance(rules, dict) else []

        if rule_items:
            for rule in rule_items:
                sse_algorithm = rule.get("applyServerSideEncryptionByDefault", {}).get(
                    "sSEAlgorithm", "unknown"
                )
                return f"S3 bucket encryption configured: {bucket_name} - algorithm: {sse_algorithm}"

        return f"S3 bucket encryption configured: {bucket_name}"

    # Lambda Event Formatters

    @staticmethod
    def format_lambda_function_created(event: dict[str, Any]) -> str:
        """Format CreateFunction event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of Lambda function creation
        """
        request_params = event.get("requestParameters", {})
        function_name = request_params.get("functionName", "unknown")
        runtime = request_params.get("runtime", "unknown")
        role = request_params.get("role", "")

        message = f"Lambda function created: {function_name} (runtime: {runtime})"

        # Extract role name from ARN
        if role and "/" in role:
            role_name = role.split("/")[-1]
            message += f", role: {role_name}"

        return message

    @staticmethod
    def format_lambda_permission_added(event: dict[str, Any]) -> str:
        """Format AddPermission event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of permission grant
        """
        request_params = event.get("requestParameters", {})
        function_name = request_params.get("functionName", "unknown")
        principal = request_params.get("principal", "unknown")
        action = request_params.get("action", "unknown")
        statement_id = request_params.get("statementId", "")

        message = (
            f"Lambda permission added: {function_name} - allows {principal} to {action}"
        )

        if principal == "*":
            message = (
                f"⚠️ Lambda function made PUBLIC: {function_name} - allows * to {action}"
            )

        if statement_id:
            message += f" (statement: {statement_id})"

        return message

    @staticmethod
    def format_lambda_function_url_created(event: dict[str, Any]) -> str:
        """Format CreateFunctionUrlConfig event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of function URL creation
        """
        request_params = event.get("requestParameters", {})
        function_name = request_params.get("functionName", "unknown")
        auth_type = request_params.get("authType", "unknown")

        message = f"Lambda function URL created: {function_name} - auth: {auth_type}"

        if auth_type == "NONE":
            message = f"⚠️ Lambda function URL created with NO AUTH: {function_name}"

        return message

    @staticmethod
    def format_lambda_code_updated(event: dict[str, Any]) -> str:
        """Format UpdateFunctionCode event.

        Args:
            event: CloudTrail event dict

        Returns:
            Description of code update
        """
        request_params = event.get("requestParameters", {})
        function_name = request_params.get("functionName", "unknown")

        update_source = []
        if "s3Bucket" in request_params:
            bucket = request_params["s3Bucket"]
            key = request_params.get("s3Key", "")
            update_source.append(f"from S3: s3://{bucket}/{key}")
        elif "imageUri" in request_params:
            update_source.append(f"from container: {request_params['imageUri']}")
        elif "zipFile" in request_params:
            update_source.append("from inline zip")

        source_desc = update_source[0] if update_source else "source unknown"
        return f"Lambda function code updated: {function_name} - {source_desc}"

    # VPC Event Formatters

    @staticmethod
    def format_subnet_created(event: dict[str, Any]) -> str:
        """Format CreateSubnet event."""
        request_params = event.get("requestParameters", {})
        subnet_id = request_params.get("subnetId", "unknown")
        cidr_block = request_params.get("cidrBlock", "unknown")
        availability_zone = request_params.get("availabilityZone", "unknown")

        return (
            f"Subnet created: {subnet_id} (CIDR: {cidr_block}, AZ: {availability_zone})"
        )

    @staticmethod
    def format_subnet_modified(event: dict[str, Any]) -> str:
        """Format ModifySubnetAttribute event."""
        request_params = event.get("requestParameters", {})
        subnet_id = request_params.get("subnetId", "unknown")

        modifications = []
        if "mapPublicIpOnLaunch" in request_params:
            auto_assign = request_params["mapPublicIpOnLaunch"].get("value", False)
            if auto_assign:
                modifications.append("⚠️ AUTO-ASSIGN PUBLIC IP ENABLED")
            else:
                modifications.append("auto-assign public IP disabled")

        if modifications:
            return f"Subnet modified: {subnet_id} - {', '.join(modifications)}"
        return f"Subnet modified: {subnet_id}"

    @staticmethod
    def format_route_created(event: dict[str, Any]) -> str:
        """Format CreateRoute event."""
        request_params = event.get("requestParameters", {})
        route_table_id = request_params.get("routeTableId", "unknown")
        destination_cidr = request_params.get(
            "destinationCidrBlock",
            request_params.get("destinationIpv6CidrBlock", "unknown"),
        )

        target = "unknown"
        if "gatewayId" in request_params:
            gateway_id = request_params["gatewayId"]
            if gateway_id.startswith("igw-"):
                target = f"internet gateway {gateway_id}"
            else:
                target = f"gateway {gateway_id}"
        elif "natGatewayId" in request_params:
            target = f"NAT gateway {request_params['natGatewayId']}"
        elif "vpcPeeringConnectionId" in request_params:
            target = f"VPC peering {request_params['vpcPeeringConnectionId']}"

        message = f"Route created: {destination_cidr} -> {target} in {route_table_id}"

        if "igw-" in target and destination_cidr in ["0.0.0.0/0", "::/0"]:
            message = f"⚠️ PUBLIC ROUTE created: {destination_cidr} -> {target} in {route_table_id}"

        return message

    @staticmethod
    def format_internet_gateway_attached(event: dict[str, Any]) -> str:
        """Format AttachInternetGateway event."""
        request_params = event.get("requestParameters", {})
        igw_id = request_params.get("internetGatewayId", "unknown")
        vpc_id = request_params.get("vpcId", "unknown")

        return f"⚠️ Internet gateway attached: {igw_id} to VPC {vpc_id}"

    @staticmethod
    def format_vpc_endpoint_created(event: dict[str, Any]) -> str:
        """Format CreateVpcEndpoint event."""
        request_params = event.get("requestParameters", {})
        service_name = request_params.get("serviceName", "unknown")
        vpc_id = request_params.get("vpcId", "unknown")
        endpoint_type = request_params.get("vpcEndpointType", "Gateway")

        return f"VPC endpoint created: {service_name} ({endpoint_type}) in {vpc_id}"

    # ELBv2 Event Formatters

    @staticmethod
    def format_elbv2_load_balancer_created(event: dict[str, Any]) -> str:
        """Format CreateLoadBalancer event for ALB/NLB."""
        request_params = event.get("requestParameters", {})
        lb_name = request_params.get("name", "unknown")
        lb_type = request_params.get("type", "application")
        scheme = request_params.get("scheme", "internet-facing")

        message = (
            f"Load balancer created: {lb_name} (type: {lb_type}, scheme: {scheme})"
        )

        if scheme == "internet-facing":
            message += " - ⚠️ INTERNET-FACING"

        return message

    @staticmethod
    def format_elbv2_listener_created(event: dict[str, Any]) -> str:
        """Format CreateListener event."""
        request_params = event.get("requestParameters", {})
        protocol = request_params.get("protocol", "unknown")
        port = request_params.get("port", "unknown")

        message = f"Listener created: {protocol}:{port}"

        default_actions = request_params.get("defaultActions", [])
        if isinstance(default_actions, dict):
            default_actions = default_actions.get("items", [])

        for action in default_actions:
            if isinstance(action, dict):
                action_type = action.get("type", "")
                if (
                    action_type == "authenticate-oidc"
                    or action_type == "authenticate-cognito"
                ):
                    message += " with authentication"
                    break

        if protocol == "HTTP":
            message = f"⚠️ Listener created with UNENCRYPTED protocol: {protocol}:{port}"

        return message

    # IAM Event Formatters

    @staticmethod
    def format_iam_user_created(event: dict[str, Any]) -> str:
        """Format CreateUser event."""
        request_params = event.get("requestParameters", {})
        user_name = request_params.get("userName", "unknown")

        return f"IAM user created: {user_name}"

    @staticmethod
    def format_iam_role_created(event: dict[str, Any]) -> str:
        """Format CreateRole event."""
        request_params = event.get("requestParameters", {})
        role_name = request_params.get("roleName", "unknown")

        assume_role_policy = request_params.get("assumeRolePolicyDocument", "")
        if isinstance(assume_role_policy, str):
            import json

            try:
                policy_doc = json.loads(assume_role_policy)
                statements = policy_doc.get("Statement", [])
                principals = []
                for stmt in statements:
                    if isinstance(stmt, dict):
                        principal = stmt.get("Principal", {})
                        if isinstance(principal, dict):
                            service = principal.get("Service", [])
                            if service:
                                if isinstance(service, list):
                                    principals.extend(service)
                                else:
                                    principals.append(service)

                if principals:
                    return f"IAM role created: {role_name} (trusted by: {', '.join(principals[:3])})"
            except Exception as e:
                logger.error(f"Error parsing IAM role policy: {e}")

        return f"IAM role created: {role_name}"

    @staticmethod
    def format_iam_policy_attached(event: dict[str, Any]) -> str:
        """Format AttachUserPolicy/AttachRolePolicy event."""
        request_params = event.get("requestParameters", {})
        policy_arn = request_params.get("policyArn", "unknown")

        target_name = (
            request_params.get("userName")
            or request_params.get("roleName")
            or request_params.get("groupName", "unknown")
        )
        target_type = (
            "user"
            if "userName" in request_params
            else "role" if "roleName" in request_params else "group"
        )

        message = f"IAM policy attached: {policy_arn} to {target_type} {target_name}"

        if "AdministratorAccess" in policy_arn or "FullAccess" in policy_arn:
            message = f"⚠️ PRIVILEGED policy attached: {policy_arn} to {target_type} {target_name}"

        return message

    @staticmethod
    def format_iam_access_key_created(event: dict[str, Any]) -> str:
        """Format CreateAccessKey event."""
        request_params = event.get("requestParameters", {})
        user_name = request_params.get("userName", "unknown")

        response_elements = event.get("responseElements", {})
        access_key = response_elements.get("accessKey", {})
        if isinstance(access_key, dict):
            key_id = access_key.get("accessKeyId", "unknown")
            return f"Access key created: {key_id} for user {user_name}"

        return f"Access key created for user: {user_name}"

    # DynamoDB Event Formatters

    @staticmethod
    def format_dynamodb_table_created(event: dict[str, Any]) -> str:
        """Format CreateTable event."""
        request_params = event.get("requestParameters", {})
        table_name = request_params.get("tableName", "unknown")

        sse_specification = request_params.get("sSESpecification", {})
        encryption_enabled = (
            sse_specification.get("enabled", False)
            if isinstance(sse_specification, dict)
            else False
        )

        message = f"DynamoDB table created: {table_name}"

        if not encryption_enabled:
            message += " - ⚠️ ENCRYPTION NOT ENABLED"
        else:
            sse_type = sse_specification.get("sSEType", "KMS")
            message += f" (encryption: {sse_type})"

        return message

    @staticmethod
    def format_dynamodb_pitr_updated(event: dict[str, Any]) -> str:
        """Format UpdateContinuousBackups event."""
        request_params = event.get("requestParameters", {})
        table_name = request_params.get("tableName", "unknown")

        pitr_spec = request_params.get("pointInTimeRecoverySpecification", {})
        enabled = (
            pitr_spec.get("pointInTimeRecoveryEnabled", False)
            if isinstance(pitr_spec, dict)
            else False
        )

        if enabled:
            return f"DynamoDB PITR enabled: {table_name}"
        else:
            return f"⚠️ DynamoDB PITR disabled: {table_name}"

    # ========== KMS Formatters ==========

    @staticmethod
    def format_kms_key_created(event: dict[str, Any]) -> str:
        """Format CreateKey event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        key_id = response_elements.get("keyMetadata", {}).get("keyId", "unknown")
        description = request_params.get("description", "")
        key_usage = request_params.get("keyUsage", "ENCRYPT_DECRYPT")
        multi_region = request_params.get("multiRegion", False)

        message = f"KMS key created: {key_id} (usage: {key_usage})"
        if description:
            message += f" - {description}"
        if multi_region:
            message += " - Multi-region key"

        return message

    @staticmethod
    def format_kms_key_deletion_scheduled(event: dict[str, Any]) -> str:
        """Format ScheduleKeyDeletion event."""
        request_params = event.get("requestParameters", {})

        key_id = request_params.get("keyId", "unknown")
        pending_window_days = request_params.get("pendingWindowInDays", 30)

        return f"⚠️ KMS KEY DELETION SCHEDULED: {key_id} (pending period: {pending_window_days} days)"

    @staticmethod
    def format_kms_key_deletion_cancelled(event: dict[str, Any]) -> str:
        """Format CancelKeyDeletion event."""
        request_params = event.get("requestParameters", {})
        key_id = request_params.get("keyId", "unknown")

        return f"KMS key deletion cancelled: {key_id}"

    @staticmethod
    def format_kms_key_disabled(event: dict[str, Any]) -> str:
        """Format DisableKey event."""
        request_params = event.get("requestParameters", {})
        key_id = request_params.get("keyId", "unknown")

        return f"⚠️ KMS KEY DISABLED: {key_id}"

    @staticmethod
    def format_kms_key_enabled(event: dict[str, Any]) -> str:
        """Format EnableKey event."""
        request_params = event.get("requestParameters", {})
        key_id = request_params.get("keyId", "unknown")

        return f"KMS key enabled: {key_id}"

    @staticmethod
    def format_kms_key_rotation_enabled(event: dict[str, Any]) -> str:
        """Format EnableKeyRotation event."""
        request_params = event.get("requestParameters", {})
        key_id = request_params.get("keyId", "unknown")

        return f"KMS key rotation enabled: {key_id}"

    @staticmethod
    def format_kms_key_rotation_disabled(event: dict[str, Any]) -> str:
        """Format DisableKeyRotation event."""
        request_params = event.get("requestParameters", {})
        key_id = request_params.get("keyId", "unknown")

        return f"⚠️ KMS KEY ROTATION DISABLED: {key_id}"

    @staticmethod
    def format_kms_key_policy_changed(event: dict[str, Any]) -> str:
        """Format PutKeyPolicy event."""
        request_params = event.get("requestParameters", {})

        key_id = request_params.get("keyId", "unknown")
        policy_name = request_params.get("policyName", "default")
        policy = request_params.get("policy", "")

        message = f"KMS key policy changed: {key_id} (policy: {policy_name})"

        # Check for public access in policy
        if policy:
            try:
                import json

                if isinstance(policy, str):
                    policy_doc = json.loads(policy)
                else:
                    policy_doc = policy

                # Check for wildcard principals
                for statement in policy_doc.get("Statement", []):
                    principal = statement.get("Principal", {})
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        message = f"⚠️ KMS KEY POLICY ALLOWS PUBLIC ACCESS: {key_id}"
                        break
            except Exception as e:
                logger.error(f"Error parsing KMS key policy: {e}")

        return message

    @staticmethod
    def format_kms_key_imported(event: dict[str, Any]) -> str:
        """Format ImportKeyMaterial event."""
        request_params = event.get("requestParameters", {})

        key_id = request_params.get("keyId", "unknown")
        expiration_model = request_params.get("expirationModel", "")

        message = f"KMS key material imported: {key_id}"
        if expiration_model:
            message += f" (expiration: {expiration_model})"

        return message

    @staticmethod
    def format_kms_grant_created(event: dict[str, Any]) -> str:
        """Format CreateGrant event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        key_id = request_params.get("keyId", "unknown")
        grantee_principal = request_params.get("granteePrincipal", "unknown")
        operations = request_params.get("operations", [])
        grant_id = response_elements.get("grantId", "unknown")

        ops_str = ", ".join(operations) if operations else "all"
        message = f"KMS grant created: {grant_id} for key {key_id}"
        message += f" (grantee: {grantee_principal}, operations: {ops_str})"

        # Warn if granting decrypt or encrypt to external account
        if grantee_principal != "unknown" and ":root" in grantee_principal:
            if any(
                op in operations for op in ["Decrypt", "Encrypt", "GenerateDataKey"]
            ):
                message = f"⚠️ {message} - CROSS-ACCOUNT ACCESS GRANTED"

        return message

    @staticmethod
    def format_kms_grant_revoked(event: dict[str, Any]) -> str:
        """Format RevokeGrant event."""
        request_params = event.get("requestParameters", {})

        key_id = request_params.get("keyId", "unknown")
        grant_id = request_params.get("grantId", "unknown")

        return f"KMS grant revoked: {grant_id} for key {key_id}"

    # ========== CloudTrail Formatters ==========

    @staticmethod
    def format_cloudtrail_trail_created(event: dict[str, Any]) -> str:
        """Format CreateTrail event."""
        request_params = event.get("requestParameters", {})

        trail_name = request_params.get("name", "unknown")
        s3_bucket = request_params.get("s3BucketName", "")
        multi_region = request_params.get("isMultiRegionTrail", False)
        log_file_validation = request_params.get("enableLogFileValidation", False)

        message = f"CloudTrail trail created: {trail_name}"
        if s3_bucket:
            message += f" (S3: {s3_bucket})"
        if multi_region:
            message += " - Multi-region trail"
        if not log_file_validation:
            message = f"⚠️ {message} - LOG FILE VALIDATION DISABLED"

        return message

    @staticmethod
    def format_cloudtrail_trail_deleted(event: dict[str, Any]) -> str:
        """Format DeleteTrail event."""
        request_params = event.get("requestParameters", {})
        trail_name = request_params.get("name", "unknown")

        return f"⚠️ CLOUDTRAIL TRAIL DELETED: {trail_name}"

    @staticmethod
    def format_cloudtrail_trail_updated(event: dict[str, Any]) -> str:
        """Format UpdateTrail event."""
        request_params = event.get("requestParameters", {})

        trail_name = request_params.get("name", "unknown")
        s3_bucket = request_params.get("s3BucketName")
        log_file_validation = request_params.get("enableLogFileValidation")

        message = f"CloudTrail trail updated: {trail_name}"
        if s3_bucket:
            message += f" (S3 bucket: {s3_bucket})"
        if log_file_validation is False:
            message = f"⚠️ {message} - LOG FILE VALIDATION DISABLED"

        return message

    @staticmethod
    def format_cloudtrail_logging_stopped(event: dict[str, Any]) -> str:
        """Format StopLogging event."""
        request_params = event.get("requestParameters", {})
        trail_name = request_params.get("name", "unknown")

        return f"⚠️ CLOUDTRAIL LOGGING STOPPED: {trail_name}"

    @staticmethod
    def format_cloudtrail_logging_started(event: dict[str, Any]) -> str:
        """Format StartLogging event."""
        request_params = event.get("requestParameters", {})
        trail_name = request_params.get("name", "unknown")

        return f"CloudTrail logging started: {trail_name}"

    @staticmethod
    def format_cloudtrail_event_selectors_updated(event: dict[str, Any]) -> str:
        """Format PutEventSelectors event."""
        request_params = event.get("requestParameters", {})

        trail_name = request_params.get("trailName", "unknown")
        event_selectors = request_params.get("eventSelectors", [])

        # Check if management events are disabled
        management_disabled = False
        for selector in event_selectors:
            if selector.get("IncludeManagementEvents") is False:
                management_disabled = True
                break

        message = f"CloudTrail event selectors updated: {trail_name}"
        if management_disabled:
            message = f"⚠️ {message} - MANAGEMENT EVENTS DISABLED"

        return message

    # ========== EBS Formatters ==========

    @staticmethod
    def format_ebs_volume_created(event: dict[str, Any]) -> str:
        """Format CreateVolume event."""
        request_params = event.get("requestParameters", {})

        volume_id = request_params.get("volumeId", "unknown")
        size = request_params.get("size", "unknown")
        volume_type = request_params.get("volumeType", "gp2")
        encrypted = request_params.get("encrypted", False)
        availability_zone = request_params.get("availabilityZone", "")

        message = f"EBS volume created: {volume_id} ({size}GB, {volume_type})"
        if availability_zone:
            message += f" in {availability_zone}"
        if not encrypted:
            message = f"⚠️ {message} - ENCRYPTION NOT ENABLED"

        return message

    @staticmethod
    def format_ebs_volume_deleted(event: dict[str, Any]) -> str:
        """Format DeleteVolume event."""
        request_params = event.get("requestParameters", {})
        volume_id = request_params.get("volumeId", "unknown")

        return f"EBS volume deleted: {volume_id}"

    @staticmethod
    def format_ebs_volume_modified(event: dict[str, Any]) -> str:
        """Format ModifyVolume event."""
        request_params = event.get("requestParameters", {})

        volume_id = request_params.get("volumeId", "unknown")
        size = request_params.get("size")
        volume_type = request_params.get("volumeType")
        iops = request_params.get("iops")

        changes = []
        if size:
            changes.append(f"size: {size}GB")
        if volume_type:
            changes.append(f"type: {volume_type}")
        if iops:
            changes.append(f"IOPS: {iops}")

        message = f"EBS volume modified: {volume_id}"
        if changes:
            message += f" ({', '.join(changes)})"

        return message

    @staticmethod
    def format_ebs_snapshot_created(event: dict[str, Any]) -> str:
        """Format CreateSnapshot event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        snapshot_id = response_elements.get("snapshotId", "unknown")
        volume_id = request_params.get("volumeId", "unknown")
        description = request_params.get("description", "")

        message = f"EBS snapshot created: {snapshot_id} from volume {volume_id}"
        if description:
            message += f" - {description}"

        return message

    @staticmethod
    def format_ebs_snapshot_deleted(event: dict[str, Any]) -> str:
        """Format DeleteSnapshot event."""
        request_params = event.get("requestParameters", {})
        snapshot_id = request_params.get("snapshotId", "unknown")

        return f"EBS snapshot deleted: {snapshot_id}"

    @staticmethod
    def format_ebs_snapshot_shared(event: dict[str, Any]) -> str:
        """Format ModifySnapshotAttribute event."""
        request_params = event.get("requestParameters", {})

        snapshot_id = request_params.get("snapshotId", "unknown")
        create_volume_permission = request_params.get("createVolumePermission", {})
        add_items = create_volume_permission.get("add", {}).get("items", [])

        # Check if snapshot is made public
        for item in add_items:
            if item.get("group") == "all":
                return f"⚠️ EBS SNAPSHOT MADE PUBLIC: {snapshot_id}"

        # Check for specific user IDs
        user_ids = [item.get("userId") for item in add_items if item.get("userId")]
        if user_ids:
            return f"EBS snapshot shared: {snapshot_id} with {len(user_ids)} account(s)"

        return f"EBS snapshot permissions modified: {snapshot_id}"

    @staticmethod
    def format_ebs_encryption_enabled(event: dict[str, Any]) -> str:
        """Format EnableEbsEncryptionByDefault event."""
        return "EBS encryption by default enabled for region"

    @staticmethod
    def format_ebs_encryption_disabled(event: dict[str, Any]) -> str:
        """Format DisableEbsEncryptionByDefault event."""
        return "⚠️ EBS ENCRYPTION BY DEFAULT DISABLED FOR REGION"

    # ========== Secrets Manager Formatters ==========

    @staticmethod
    def format_secrets_manager_secret_created(event: dict[str, Any]) -> str:
        """Format CreateSecret event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        secret_name = request_params.get("name", "unknown")
        response_elements.get("aRN", "")
        kms_key_id = request_params.get("kmsKeyId")
        description = request_params.get("description", "")

        message = f"Secret created: {secret_name}"
        if description:
            message += f" - {description}"
        if not kms_key_id:
            message = f"⚠️ {message} - USING DEFAULT ENCRYPTION KEY"

        return message

    @staticmethod
    def format_secrets_manager_secret_deleted(event: dict[str, Any]) -> str:
        """Format DeleteSecret event."""
        request_params = event.get("requestParameters", {})

        secret_id = request_params.get("secretId", "unknown")
        recovery_window = request_params.get("recoveryWindowInDays", 30)
        force_delete = request_params.get("forceDeleteWithoutRecovery", False)

        if force_delete:
            return f"⚠️ SECRET PERMANENTLY DELETED (NO RECOVERY): {secret_id}"
        else:
            return f"Secret deletion scheduled: {secret_id} (recovery window: {recovery_window} days)"

    @staticmethod
    def format_secrets_manager_secret_updated(event: dict[str, Any]) -> str:
        """Format UpdateSecret or PutSecretValue event."""
        request_params = event.get("requestParameters", {})

        secret_id = request_params.get("secretId", "unknown")
        description = request_params.get("description")
        kms_key_id = request_params.get("kmsKeyId")

        message = f"Secret updated: {secret_id}"
        if description:
            message += f" - {description}"
        if kms_key_id:
            message += f" (KMS key: {kms_key_id})"

        return message

    @staticmethod
    def format_secrets_manager_secret_rotated(event: dict[str, Any]) -> str:
        """Format RotateSecret event."""
        request_params = event.get("requestParameters", {})

        secret_id = request_params.get("secretId", "unknown")
        rotation_lambda = request_params.get("rotationLambdaARN", "")

        message = f"Secret rotated: {secret_id}"
        if rotation_lambda:
            lambda_name = rotation_lambda.split(":")[-1]
            message += f" (Lambda: {lambda_name})"

        return message

    @staticmethod
    def format_secrets_manager_rotation_enabled(event: dict[str, Any]) -> str:
        """Format RotateSecret event when enabling rotation."""
        request_params = event.get("requestParameters", {})

        secret_id = request_params.get("secretId", "unknown")
        rotation_rules = request_params.get("rotationRules", {})
        automatically_after_days = rotation_rules.get(
            "automaticallyAfterDays", "unknown"
        )
        rotation_lambda = request_params.get("rotationLambdaARN", "")

        message = f"Secret rotation enabled: {secret_id} (every {automatically_after_days} days)"
        if rotation_lambda:
            lambda_name = rotation_lambda.split(":")[-1]
            message += f" using Lambda: {lambda_name}"

        return message

    @staticmethod
    def format_secrets_manager_rotation_disabled(event: dict[str, Any]) -> str:
        """Format CancelRotateSecret or RemoveRotation event."""
        request_params = event.get("requestParameters", {})
        secret_id = request_params.get("secretId", "unknown")

        return f"⚠️ SECRET ROTATION DISABLED: {secret_id}"

    @staticmethod
    def format_secrets_manager_policy_changed(event: dict[str, Any]) -> str:
        """Format PutResourcePolicy event."""
        request_params = event.get("requestParameters", {})

        secret_id = request_params.get("secretId", "unknown")
        resource_policy = request_params.get("resourcePolicy", "")

        # Check for public access in policy
        if resource_policy:
            try:
                import json

                policy_doc = (
                    json.loads(resource_policy)
                    if isinstance(resource_policy, str)
                    else resource_policy
                )
                for statement in policy_doc.get("Statement", []):
                    principal = statement.get("Principal", {})
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        return f"⚠️ SECRET POLICY ALLOWS PUBLIC ACCESS: {secret_id}"
            except Exception as e:
                logger.error(f"Error parsing secret policy: {e}")

        return f"Secret resource policy changed: {secret_id}"

    # ========== CloudWatch Formatters ==========

    @staticmethod
    def format_cloudwatch_alarm_created(event: dict[str, Any]) -> str:
        """Format PutMetricAlarm event."""
        request_params = event.get("requestParameters", {})

        alarm_name = request_params.get("alarmName", "unknown")
        metric_name = request_params.get("metricName", "")
        namespace = request_params.get("namespace", "")
        comparison_operator = request_params.get("comparisonOperator", "")
        threshold = request_params.get("threshold", "")
        actions_enabled = request_params.get("actionsEnabled", True)

        message = f"CloudWatch alarm created: {alarm_name}"
        if metric_name and namespace:
            message += f" (metric: {namespace}/{metric_name})"
        if comparison_operator and threshold:
            message += f" - {comparison_operator} {threshold}"
        if not actions_enabled:
            message = f"⚠️ {message} - ACTIONS DISABLED"

        return message

    @staticmethod
    def format_cloudwatch_alarm_deleted(event: dict[str, Any]) -> str:
        """Format DeleteAlarms event."""
        request_params = event.get("requestParameters", {})
        alarm_names = request_params.get("alarmNames", [])

        if isinstance(alarm_names, list) and alarm_names:
            if len(alarm_names) == 1:
                return f"CloudWatch alarm deleted: {alarm_names[0]}"
            else:
                return f"⚠️ CloudWatch alarms deleted: {len(alarm_names)} alarms ({', '.join(alarm_names[:3])}{'...' if len(alarm_names) > 3 else ''})"

        return "CloudWatch alarm(s) deleted"

    @staticmethod
    def format_cloudwatch_alarm_updated(event: dict[str, Any]) -> str:
        """Format PutMetricAlarm event for alarm update."""
        request_params = event.get("requestParameters", {})

        alarm_name = request_params.get("alarmName", "unknown")
        actions_enabled = request_params.get("actionsEnabled")
        threshold = request_params.get("threshold")
        comparison_operator = request_params.get("comparisonOperator")

        changes = []
        if threshold is not None:
            changes.append(f"threshold: {threshold}")
        if comparison_operator:
            changes.append(f"operator: {comparison_operator}")
        if actions_enabled is False:
            changes.append("⚠️ actions disabled")

        message = f"CloudWatch alarm updated: {alarm_name}"
        if changes:
            message += f" ({', '.join(changes)})"

        return message

    @staticmethod
    def format_cloudwatch_alarm_state_changed(event: dict[str, Any]) -> str:
        """Format SetAlarmState event."""
        request_params = event.get("requestParameters", {})

        alarm_name = request_params.get("alarmName", "unknown")
        state_value = request_params.get("stateValue", "unknown")
        state_reason = request_params.get("stateReason", "")

        message = f"CloudWatch alarm state changed: {alarm_name} -> {state_value}"
        if state_reason:
            message += f" ({state_reason})"

        return message

    @staticmethod
    def format_cloudwatch_alarm_actions_disabled(event: dict[str, Any]) -> str:
        """Format DisableAlarmActions event."""
        request_params = event.get("requestParameters", {})
        alarm_names = request_params.get("alarmNames", [])

        if isinstance(alarm_names, list) and alarm_names:
            if len(alarm_names) == 1:
                return f"⚠️ CLOUDWATCH ALARM ACTIONS DISABLED: {alarm_names[0]}"
            else:
                return f"⚠️ CLOUDWATCH ALARM ACTIONS DISABLED: {len(alarm_names)} alarms"

        return "⚠️ CloudWatch alarm actions disabled"

    @staticmethod
    def format_cloudwatch_alarm_actions_enabled(event: dict[str, Any]) -> str:
        """Format EnableAlarmActions event."""
        request_params = event.get("requestParameters", {})
        alarm_names = request_params.get("alarmNames", [])

        if isinstance(alarm_names, list) and alarm_names:
            if len(alarm_names) == 1:
                return f"CloudWatch alarm actions enabled: {alarm_names[0]}"
            else:
                return f"CloudWatch alarm actions enabled: {len(alarm_names)} alarms"

        return "CloudWatch alarm actions enabled"

    @staticmethod
    def format_cloudwatch_log_group_created(event: dict[str, Any]) -> str:
        """Format CreateLogGroup event."""
        request_params = event.get("requestParameters", {})
        log_group_name = request_params.get("logGroupName", "unknown")

        return f"CloudWatch log group created: {log_group_name}"

    @staticmethod
    def format_cloudwatch_log_group_deleted(event: dict[str, Any]) -> str:
        """Format DeleteLogGroup event."""
        request_params = event.get("requestParameters", {})
        log_group_name = request_params.get("logGroupName", "unknown")

        return f"CloudWatch log group deleted: {log_group_name}"

    @staticmethod
    def format_cloudwatch_log_retention_changed(event: dict[str, Any]) -> str:
        """Format PutRetentionPolicy event."""
        request_params = event.get("requestParameters", {})

        log_group_name = request_params.get("logGroupName", "unknown")
        retention_days = request_params.get("retentionInDays")

        message = f"CloudWatch log retention changed: {log_group_name}"
        if retention_days is not None:
            if retention_days == 0:
                message += " - Never expire"
            else:
                message += f" - {retention_days} days"
                if retention_days < 7:
                    message = f"⚠️ {message} (SHORT RETENTION PERIOD)"

        return message

    # ========== SNS Formatters ==========

    @staticmethod
    def format_sns_topic_created(event: dict[str, Any]) -> str:
        """Format CreateTopic event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        topic_name = request_params.get("name", "unknown")
        topic_arn = response_elements.get("topicArn", "")

        message = f"SNS topic created: {topic_name}"
        if topic_arn:
            message += f" (ARN: {topic_arn})"

        return message

    @staticmethod
    def format_sns_topic_deleted(event: dict[str, Any]) -> str:
        """Format DeleteTopic event."""
        request_params = event.get("requestParameters", {})

        topic_arn = request_params.get("topicArn", "unknown")

        return f"SNS topic deleted: {topic_arn}"

    @staticmethod
    def format_sns_topic_attribute_changed(event: dict[str, Any]) -> str:
        """Format SetTopicAttributes event."""
        request_params = event.get("requestParameters", {})

        topic_arn = request_params.get("topicArn", "unknown")
        attribute_name = request_params.get("attributeName", "unknown")
        attribute_value = request_params.get("attributeValue", "")

        message = f"SNS topic attribute changed: {topic_arn} - {attribute_name}"

        # Check for public access in policy
        if attribute_name == "Policy" and attribute_value:
            if (
                '"Principal":"*"' in attribute_value
                or '"Principal":{"AWS":"*"}' in attribute_value
            ):
                message = f"⚠️ SNS TOPIC POLICY ALLOWS PUBLIC ACCESS: {topic_arn}"
            elif "Condition" not in attribute_value and "*" in attribute_value:
                message = f"⚠️ {message} (contains wildcards without conditions)"

        return message

    @staticmethod
    def format_sns_subscription_created(event: dict[str, Any]) -> str:
        """Format Subscribe event."""
        request_params = event.get("requestParameters", {})

        topic_arn = request_params.get("topicArn", "unknown")
        protocol = request_params.get("protocol", "")
        endpoint = request_params.get("endpoint", "")

        message = f"SNS subscription created: {topic_arn}"
        if protocol:
            message += f" (protocol: {protocol}"
            if endpoint:
                # Truncate long endpoints
                if len(endpoint) > 50:
                    endpoint = endpoint[:47] + "..."
                message += f", endpoint: {endpoint}"
            message += ")"

        # Warn on potentially insecure protocols
        if protocol in ["http", "email", "email-json"]:
            message = f"⚠️ {message} - UNENCRYPTED PROTOCOL"

        return message

    @staticmethod
    def format_sns_subscription_deleted(event: dict[str, Any]) -> str:
        """Format Unsubscribe event."""
        request_params = event.get("requestParameters", {})

        subscription_arn = request_params.get("subscriptionArn", "unknown")

        return f"SNS subscription deleted: {subscription_arn}"

    # ========== SQS Formatters ==========

    @staticmethod
    def format_sqs_queue_created(event: dict[str, Any]) -> str:
        """Format CreateQueue event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        queue_name = request_params.get("queueName", "unknown")
        queue_url = response_elements.get("queueUrl", "")
        attributes = request_params.get("attributes", {})

        message = f"SQS queue created: {queue_name}"
        if queue_url:
            message += f" (URL: {queue_url})"

        # Check for encryption
        kms_key = attributes.get("KmsMasterKeyId") if attributes else None
        if not kms_key:
            message = f"⚠️ {message} - ENCRYPTION NOT ENABLED"

        return message

    @staticmethod
    def format_sqs_queue_deleted(event: dict[str, Any]) -> str:
        """Format DeleteQueue event."""
        request_params = event.get("requestParameters", {})

        queue_url = request_params.get("queueUrl", "unknown")

        return f"SQS queue deleted: {queue_url}"

    @staticmethod
    def format_sqs_queue_attribute_changed(event: dict[str, Any]) -> str:
        """Format SetQueueAttributes event."""
        request_params = event.get("requestParameters", {})

        queue_url = request_params.get("queueUrl", "unknown")
        attributes = request_params.get("attributes", {})

        if not attributes:
            return f"SQS queue attributes changed: {queue_url}"

        # Check what was changed
        changed_attrs = list(attributes.keys())
        message = (
            f"SQS queue attributes changed: {queue_url} - {', '.join(changed_attrs)}"
        )

        # Check for encryption being disabled
        if "KmsMasterKeyId" in attributes and not attributes["KmsMasterKeyId"]:
            message = f"⚠️ SQS QUEUE ENCRYPTION DISABLED: {queue_url}"

        return message

    @staticmethod
    def format_sqs_queue_policy_changed(event: dict[str, Any]) -> str:
        """Format SetQueueAttributes event with Policy changes."""
        request_params = event.get("requestParameters", {})

        queue_url = request_params.get("queueUrl", "unknown")
        attributes = request_params.get("attributes", {})
        policy = attributes.get("Policy", "") if attributes else ""

        message = f"SQS queue policy changed: {queue_url}"

        # Check for public access in policy
        if policy:
            if '"Principal":"*"' in policy or '"Principal":{"AWS":"*"}' in policy:
                message = f"⚠️ SQS QUEUE POLICY ALLOWS PUBLIC ACCESS: {queue_url}"
            elif "Condition" not in policy and "*" in policy:
                message = f"⚠️ {message} (contains wildcards without conditions)"

        return message

    # ========== ECR Formatters ==========

    @staticmethod
    def format_ecr_repository_created(event: dict[str, Any]) -> str:
        """Format CreateRepository event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        repository_name = request_params.get("repositoryName", "unknown")
        repository_info = response_elements.get("repository", {})
        repository_uri = repository_info.get("repositoryUri", "")
        encryption_config = request_params.get("encryptionConfiguration", {})

        message = f"ECR repository created: {repository_name}"
        if repository_uri:
            message += f" (URI: {repository_uri})"

        # Check encryption
        encryption_type = (
            encryption_config.get("encryptionType") if encryption_config else None
        )
        if encryption_type == "AES256":
            message += " - encrypted with AES256"
        elif encryption_type == "KMS":
            kms_key = encryption_config.get("kmsKey", "default")
            message += f" - encrypted with KMS ({kms_key})"
        else:
            message = f"⚠️ {message} - ENCRYPTION NOT CONFIGURED"

        return message

    @staticmethod
    def format_ecr_repository_deleted(event: dict[str, Any]) -> str:
        """Format DeleteRepository event."""
        request_params = event.get("requestParameters", {})

        repository_name = request_params.get("repositoryName", "unknown")
        force = request_params.get("force", False)

        message = f"ECR repository deleted: {repository_name}"
        if force:
            message += " (forced deletion)"

        return message

    @staticmethod
    def format_ecr_image_pushed(event: dict[str, Any]) -> str:
        """Format PutImage event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        repository_name = request_params.get("repositoryName", "unknown")
        image_tag = request_params.get("imageTag", "")
        request_params.get("imageManifest", "")
        image_info = response_elements.get("image", {})

        message = f"ECR image pushed: {repository_name}"
        if image_tag:
            message += f":{image_tag}"
        elif image_info.get("imageId", {}).get("imageDigest"):
            digest = image_info["imageId"]["imageDigest"][:19]  # sha256:xxxxx...
            message += f" ({digest}...)"

        return message

    @staticmethod
    def format_ecr_image_deleted(event: dict[str, Any]) -> str:
        """Format BatchDeleteImage event."""
        request_params = event.get("requestParameters", {})

        repository_name = request_params.get("repositoryName", "unknown")
        image_ids = request_params.get("imageIds", [])

        if isinstance(image_ids, list) and image_ids:
            count = len(image_ids)
            message = f"ECR image(s) deleted from {repository_name}: {count} image(s)"
        else:
            message = f"ECR image deleted from {repository_name}"

        return message

    @staticmethod
    def format_ecr_lifecycle_policy_set(event: dict[str, Any]) -> str:
        """Format PutLifecyclePolicy event."""
        request_params = event.get("requestParameters", {})

        repository_name = request_params.get("repositoryName", "unknown")
        request_params.get("lifecyclePolicyText", "")

        message = f"ECR lifecycle policy set: {repository_name}"

        return message

    @staticmethod
    def format_ecr_repository_policy_set(event: dict[str, Any]) -> str:
        """Format SetRepositoryPolicy event."""
        request_params = event.get("requestParameters", {})

        repository_name = request_params.get("repositoryName", "unknown")
        policy_text = request_params.get("policyText", "")

        message = f"ECR repository policy set: {repository_name}"

        # Check for public access in policy
        if policy_text:
            if (
                '"Principal":"*"' in policy_text
                or '"Principal":{"AWS":"*"}' in policy_text
            ):
                message = (
                    f"⚠️ ECR REPOSITORY POLICY ALLOWS PUBLIC ACCESS: {repository_name}"
                )
            elif "Condition" not in policy_text and "*" in policy_text:
                message = f"⚠️ {message} (contains wildcards without conditions)"

        return message

    @staticmethod
    def format_ecr_image_scan_configured(event: dict[str, Any]) -> str:
        """Format PutImageScanningConfiguration event."""
        request_params = event.get("requestParameters", {})

        repository_name = request_params.get("repositoryName", "unknown")
        scan_config = request_params.get("imageScanningConfiguration", {})
        scan_on_push = scan_config.get("scanOnPush", False) if scan_config else False

        message = f"ECR image scanning configured: {repository_name}"

        if scan_on_push:
            message += " - scan on push ENABLED"
        else:
            message = f"⚠️ {message} - scan on push DISABLED"

        return message

    # ========== ECS Formatters ==========

    @staticmethod
    def format_ecs_cluster_created(event: dict[str, Any]) -> str:
        """Format CreateCluster event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        cluster_name = request_params.get("clusterName", "unknown")
        cluster_info = response_elements.get("cluster", {})
        cluster_arn = cluster_info.get("clusterArn", "")

        message = f"ECS cluster created: {cluster_name}"
        if cluster_arn:
            message += f" (ARN: {cluster_arn})"

        return message

    @staticmethod
    def format_ecs_cluster_deleted(event: dict[str, Any]) -> str:
        """Format DeleteCluster event."""
        request_params = event.get("requestParameters", {})

        cluster = request_params.get("cluster", "unknown")

        return f"ECS cluster deleted: {cluster}"

    @staticmethod
    def format_ecs_service_created(event: dict[str, Any]) -> str:
        """Format CreateService event."""
        request_params = event.get("requestParameters", {})
        event.get("responseElements", {})

        service_name = request_params.get("serviceName", "unknown")
        cluster = request_params.get("cluster", "")
        task_definition = request_params.get("taskDefinition", "")
        desired_count = request_params.get("desiredCount", 0)
        launch_type = request_params.get("launchType", "")
        network_config = request_params.get("networkConfiguration", {})

        message = f"ECS service created: {service_name}"
        if cluster:
            message += f" in cluster {cluster}"
        if task_definition:
            message += f" (task: {task_definition})"
        if desired_count:
            message += f" - {desired_count} task(s)"
        if launch_type:
            message += f" - {launch_type}"

        # Check for public IP assignment
        awsvpc_config = (
            network_config.get("awsvpcConfiguration", {}) if network_config else {}
        )
        assign_public_ip = awsvpc_config.get("assignPublicIp", "")
        if assign_public_ip == "ENABLED":
            message = f"⚠️ {message} - PUBLIC IP ASSIGNED"

        return message

    @staticmethod
    def format_ecs_service_deleted(event: dict[str, Any]) -> str:
        """Format DeleteService event."""
        request_params = event.get("requestParameters", {})

        service = request_params.get("service", "unknown")
        cluster = request_params.get("cluster", "")
        force = request_params.get("force", False)

        message = f"ECS service deleted: {service}"
        if cluster:
            message += f" from cluster {cluster}"
        if force:
            message += " (forced deletion)"

        return message

    @staticmethod
    def format_ecs_service_updated(event: dict[str, Any]) -> str:
        """Format UpdateService event."""
        request_params = event.get("requestParameters", {})

        service = request_params.get("service", "unknown")
        cluster = request_params.get("cluster", "")
        desired_count = request_params.get("desiredCount")
        task_definition = request_params.get("taskDefinition")

        message = f"ECS service updated: {service}"
        if cluster:
            message += f" in cluster {cluster}"

        changes = []
        if desired_count is not None:
            changes.append(f"desired count: {desired_count}")
        if task_definition:
            changes.append(f"task: {task_definition}")

        if changes:
            message += f" - {', '.join(changes)}"

        return message

    @staticmethod
    def format_ecs_task_definition_registered(event: dict[str, Any]) -> str:
        """Format RegisterTaskDefinition event."""
        request_params = event.get("requestParameters", {})
        response_elements = event.get("responseElements", {})

        family = request_params.get("family", "unknown")
        request_params.get("taskRoleArn", "")
        request_params.get("executionRoleArn", "")
        network_mode = request_params.get("networkMode", "")
        container_definitions = request_params.get("containerDefinitions", [])

        task_def_info = response_elements.get("taskDefinition", {})
        revision = task_def_info.get("revision", "")

        message = f"ECS task definition registered: {family}"
        if revision:
            message += f":{revision}"
        if network_mode:
            message += f" (network: {network_mode})"

        # Check for privileged containers
        if isinstance(container_definitions, list):
            privileged_containers = [
                c.get("name", "unknown")
                for c in container_definitions
                if c.get("privileged", False)
            ]
            if privileged_containers:
                container_names = ", ".join(privileged_containers)
                message = f"⚠️ {message} - PRIVILEGED CONTAINER(S): {container_names}"

        return message

    @staticmethod
    def format_ecs_task_definition_deregistered(event: dict[str, Any]) -> str:
        """Format DeregisterTaskDefinition event."""
        request_params = event.get("requestParameters", {})

        task_definition = request_params.get("taskDefinition", "unknown")

        return f"ECS task definition deregistered: {task_definition}"
