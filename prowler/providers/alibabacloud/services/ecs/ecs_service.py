"""
Alibaba Cloud ECS Service

This module provides the service class for Alibaba Cloud Elastic Compute Service (ECS).
"""

from dataclasses import dataclass
from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


@dataclass
class Instance:
    """
    Represents an Alibaba Cloud ECS instance

    Attributes:
        id: Instance ID
        name: Instance name
        arn: Instance ARN
        region: Region where the instance is located
        status: Instance status (Running, Stopped, etc.)
        instance_type: Instance type/specification
        public_ip: Public IP address (if any)
        private_ip: Private IP address
        security_groups: List of security group IDs
        vpc_id: VPC ID
        zone_id: Availability zone ID
        image_id: OS image ID
        tags: Instance tags
        created_time: Creation timestamp
        expired_time: Expiration timestamp (for subscription instances)
    """

    id: str
    name: str
    arn: str
    region: str
    status: str = ""
    instance_type: str = ""
    public_ip: Optional[str] = None
    private_ip: str = ""
    security_groups: list = None
    vpc_id: str = ""
    zone_id: str = ""
    image_id: str = ""
    tags: dict = None
    created_time: str = ""
    expired_time: str = ""

    def __post_init__(self):
        if self.security_groups is None:
            self.security_groups = []
        if self.tags is None:
            self.tags = {}


@dataclass
class Disk:
    """
    Represents an Alibaba Cloud ECS disk

    Attributes:
        id: Disk ID
        name: Disk name
        arn: Disk ARN
        region: Region where the disk is located
        disk_type: Type of disk (system, data)
        category: Disk category (cloud_ssd, cloud_essd, etc.)
        size: Disk size in GB
        encrypted: Whether the disk is encrypted
        kms_key_id: KMS key ID used for encryption (if encrypted)
        status: Disk status (Available, In_use, etc.)
        instance_id: Attached instance ID (if attached)
        zone_id: Availability zone ID
        tags: Disk tags
    """

    id: str
    name: str
    arn: str
    region: str
    disk_type: str = ""
    category: str = ""
    size: int = 0
    encrypted: bool = False
    kms_key_id: Optional[str] = None
    status: str = ""
    instance_id: Optional[str] = None
    zone_id: str = ""
    tags: dict = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = {}


@dataclass
class SecurityGroup:
    """
    Represents an Alibaba Cloud security group

    Attributes:
        id: Security group ID
        name: Security group name
        arn: Security group ARN
        region: Region where the security group is located
        vpc_id: VPC ID
        description: Security group description
        rules: List of security group rules
        tags: Security group tags
    """

    id: str
    name: str
    arn: str
    region: str
    vpc_id: str = ""
    description: str = ""
    rules: list = None
    tags: dict = None

    def __post_init__(self):
        if self.rules is None:
            self.rules = []
        if self.tags is None:
            self.tags = {}


class ECS(AlibabaCloudService):
    """
    Alibaba Cloud ECS service class

    This class handles the collection of ECS resources including instances,
    disks, and security groups for auditing.
    """

    def __init__(self, provider):
        """
        Initialize ECS service

        Args:
            provider: AlibabaCloudProvider instance
        """
        super().__init__("ecs", provider)

        # Initialize resource dictionaries
        self.instances = {}
        self.disks = {}
        self.security_groups = {}

        # Collect ECS resources
        logger.info("Collecting ECS instances...")
        self._describe_instances()

        logger.info("Collecting ECS disks...")
        self._describe_disks()

        logger.info("Collecting ECS security groups...")
        self._describe_security_groups()

        logger.info(
            f"ECS service initialized - Instances: {len(self.instances)}, "
            f"Disks: {len(self.disks)}, Security Groups: {len(self.security_groups)}"
        )

    def _describe_instances(self):
        """
        Describe ECS instances across all regions

        This method collects all ECS instances and their details.
        """
        logger.info("Describing ECS instances across regions...")

        for region in self.regions:
            try:
                from alibabacloud_ecs20140526 import models
                from alibabacloud_ecs20140526.client import Client as EcsClient
                from alibabacloud_tea_openapi import models as openapi_models

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                # Add security token if present (for STS)
                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create ECS client
                client = EcsClient(config)

                # Describe instances
                request = models.DescribeInstancesRequest(
                    page_size=100, region_id=region
                )
                response = client.describe_instances(request)

                # Process instances
                if response.body.instances and response.body.instances.instance:
                    for instance_data in response.body.instances.instance:
                        instance_id = instance_data.instance_id
                        arn = self.generate_resource_arn(
                            "instance", instance_id, region
                        )

                        # Get public IP
                        public_ip = None
                        if (
                            instance_data.public_ip_address
                            and instance_data.public_ip_address.ip_address
                        ):
                            public_ip = (
                                instance_data.public_ip_address.ip_address[0]
                                if instance_data.public_ip_address.ip_address
                                else None
                            )
                        elif (
                            instance_data.eip_address
                            and instance_data.eip_address.ip_address
                        ):
                            public_ip = instance_data.eip_address.ip_address

                        # Get private IP
                        private_ip = ""
                        if (
                            instance_data.vpc_attributes
                            and instance_data.vpc_attributes.private_ip_address
                        ):
                            private_ip = (
                                instance_data.vpc_attributes.private_ip_address.ip_address[
                                    0
                                ]
                                if instance_data.vpc_attributes.private_ip_address.ip_address
                                else ""
                            )

                        # Get security groups
                        security_groups = []
                        if (
                            instance_data.security_group_ids
                            and instance_data.security_group_ids.security_group_id
                        ):
                            security_groups = (
                                instance_data.security_group_ids.security_group_id
                            )

                        # Get VPC ID
                        vpc_id = (
                            instance_data.vpc_attributes.vpc_id
                            if instance_data.vpc_attributes
                            else ""
                        )

                        # Get tags
                        tags = {}
                        if instance_data.tags and instance_data.tags.tag:
                            for tag in instance_data.tags.tag:
                                tags[tag.tag_key] = tag.tag_value

                        instance = Instance(
                            id=instance_id,
                            name=instance_data.instance_name or instance_id,
                            arn=arn,
                            region=region,
                            status=instance_data.status,
                            instance_type=instance_data.instance_type,
                            public_ip=public_ip,
                            private_ip=private_ip,
                            security_groups=security_groups,
                            vpc_id=vpc_id,
                            zone_id=instance_data.zone_id,
                            image_id=instance_data.image_id,
                            tags=tags,
                            created_time=instance_data.creation_time,
                            expired_time=(
                                instance_data.expired_time
                                if hasattr(instance_data, "expired_time")
                                else ""
                            ),
                        )

                        self.instances[arn] = instance
                        logger.info(f"Found ECS instance: {instance_id} in {region}")
                else:
                    logger.info(f"No ECS instances found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeInstances", region)

    def _describe_disks(self):
        """
        Describe ECS disks across all regions

        This method collects all ECS disks and their encryption status.
        """
        logger.info("Describing ECS disks across regions...")

        for region in self.regions:
            try:
                from alibabacloud_ecs20140526 import models
                from alibabacloud_ecs20140526.client import Client as EcsClient
                from alibabacloud_tea_openapi import models as openapi_models

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create ECS client
                client = EcsClient(config)

                # Describe disks
                request = models.DescribeDisksRequest(page_size=100, region_id=region)
                response = client.describe_disks(request)

                # Process disks
                if response.body.disks and response.body.disks.disk:
                    for disk_data in response.body.disks.disk:
                        disk_id = disk_data.disk_id
                        arn = self.generate_resource_arn("disk", disk_id, region)

                        # Get tags
                        tags = {}
                        if disk_data.tags and disk_data.tags.tag:
                            for tag in disk_data.tags.tag:
                                tags[tag.tag_key] = tag.tag_value

                        disk = Disk(
                            id=disk_id,
                            name=disk_data.disk_name or disk_id,
                            arn=arn,
                            region=region,
                            disk_type=disk_data.type if disk_data.type else "",
                            category=disk_data.category if disk_data.category else "",
                            size=disk_data.size if disk_data.size else 0,
                            encrypted=(
                                disk_data.encrypted
                                if hasattr(disk_data, "encrypted")
                                else False
                            ),
                            kms_key_id=(
                                disk_data.kms_key_id
                                if hasattr(disk_data, "kms_key_id")
                                else None
                            ),
                            status=disk_data.status if disk_data.status else "",
                            instance_id=(
                                disk_data.instance_id if disk_data.instance_id else None
                            ),
                            zone_id=disk_data.zone_id if disk_data.zone_id else "",
                            tags=tags,
                        )

                        self.disks[arn] = disk
                        logger.info(f"Found ECS disk: {disk_id} in {region}")
                else:
                    logger.info(f"No ECS disks found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeDisks", region)

    def _describe_security_groups(self):
        """
        Describe security groups and their rules

        This method collects security groups and analyzes their rules.
        """
        logger.info("Describing security groups across regions...")

        for region in self.regions:
            try:
                from alibabacloud_ecs20140526 import models
                from alibabacloud_ecs20140526.client import Client as EcsClient
                from alibabacloud_tea_openapi import models as openapi_models

                # Create client configuration
                config = openapi_models.Config(
                    access_key_id=self.provider.session.credentials.access_key_id,
                    access_key_secret=self.provider.session.credentials.access_key_secret,
                    region_id=region,
                )

                if self.provider.session.credentials.security_token:
                    config.security_token = (
                        self.provider.session.credentials.security_token
                    )

                # Create ECS client
                client = EcsClient(config)

                # Describe security groups
                request = models.DescribeSecurityGroupsRequest(
                    page_size=100, region_id=region
                )
                response = client.describe_security_groups(request)

                # Process security groups
                if (
                    response.body.security_groups
                    and response.body.security_groups.security_group
                ):
                    for sg_data in response.body.security_groups.security_group:
                        sg_id = sg_data.security_group_id
                        arn = self.generate_resource_arn(
                            "security-group", sg_id, region
                        )

                        # Get tags
                        tags = {}
                        if sg_data.tags and sg_data.tags.tag:
                            for tag in sg_data.tags.tag:
                                tags[tag.tag_key] = tag.tag_value

                        # Get security group rules
                        rules = []
                        try:
                            rules_request = (
                                models.DescribeSecurityGroupAttributeRequest(
                                    security_group_id=sg_id, region_id=region
                                )
                            )
                            rules_response = client.describe_security_group_attribute(
                                rules_request
                            )

                            # Process ingress rules
                            if (
                                rules_response.body.permissions
                                and rules_response.body.permissions.permission
                            ):
                                for perm in rules_response.body.permissions.permission:
                                    rule = {
                                        "direction": (
                                            perm.direction
                                            if perm.direction
                                            else "ingress"
                                        ),
                                        "protocol": (
                                            perm.ip_protocol if perm.ip_protocol else ""
                                        ),
                                        "port_range": (
                                            perm.port_range if perm.port_range else ""
                                        ),
                                        "source": (
                                            perm.source_cidr_ip
                                            if hasattr(perm, "source_cidr_ip")
                                            and perm.source_cidr_ip
                                            else ""
                                        ),
                                        "source_group_id": (
                                            perm.source_group_id
                                            if hasattr(perm, "source_group_id")
                                            and perm.source_group_id
                                            else ""
                                        ),
                                    }
                                    rules.append(rule)
                        except Exception as rules_error:
                            logger.warning(
                                f"Could not retrieve rules for security group {sg_id}: {rules_error}"
                            )

                        security_group = SecurityGroup(
                            id=sg_id,
                            name=sg_data.security_group_name or sg_id,
                            arn=arn,
                            region=region,
                            vpc_id=sg_data.vpc_id if sg_data.vpc_id else "",
                            description=(
                                sg_data.description if sg_data.description else ""
                            ),
                            rules=rules,
                            tags=tags,
                        )

                        self.security_groups[arn] = security_group
                        logger.info(f"Found security group: {sg_id} in {region}")
                else:
                    logger.info(f"No security groups found in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeSecurityGroups", region)
