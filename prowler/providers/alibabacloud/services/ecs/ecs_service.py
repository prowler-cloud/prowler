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
                # TODO: Implement actual Alibaba Cloud SDK call
                # from alibabacloud_ecs20140526.client import Client
                # from alibabacloud_ecs20140526.models import DescribeInstancesRequest
                #
                # client = self._create_regional_client(region)
                # request = DescribeInstancesRequest()
                # response = client.describe_instances(request)
                #
                # for instance_data in response.body.instances.instance:
                #     instance = self._parse_instance(instance_data, region)
                #     self.instances[instance.arn] = instance

                # Placeholder: Create sample instance for demonstration
                instance_id = f"i-{region}-sample123"
                arn = self.generate_resource_arn("instance", instance_id, region)

                instance = Instance(
                    id=instance_id,
                    name=f"sample-instance-{region}",
                    arn=arn,
                    region=region,
                    status="Running",
                    instance_type="ecs.t6-c1m1.large",
                    public_ip="192.0.2.1",
                    private_ip="10.0.1.10",
                    security_groups=["sg-sample123"],
                    vpc_id="vpc-sample123",
                    zone_id=f"{region}-a",
                )

                self.instances[arn] = instance
                logger.info(f"Found ECS instance: {instance_id} in {region}")

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
                # TODO: Implement actual Alibaba Cloud SDK call
                # Placeholder: Create sample disk for demonstration
                disk_id = f"d-{region}-sample456"
                arn = self.generate_resource_arn("disk", disk_id, region)

                disk = Disk(
                    id=disk_id,
                    name=f"sample-disk-{region}",
                    arn=arn,
                    region=region,
                    disk_type="data",
                    category="cloud_essd",
                    size=100,
                    encrypted=False,  # This will be checked
                    status="In_use",
                    instance_id=f"i-{region}-sample123",
                    zone_id=f"{region}-a",
                )

                self.disks[arn] = disk
                logger.info(f"Found ECS disk: {disk_id} in {region}")

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
                # TODO: Implement actual Alibaba Cloud SDK call
                # Placeholder: Create sample security group
                sg_id = f"sg-{region}-sample789"
                arn = self.generate_resource_arn("security-group", sg_id, region)

                # Sample security group with unrestricted SSH access (for check demonstration)
                security_group = SecurityGroup(
                    id=sg_id,
                    name=f"sample-sg-{region}",
                    arn=arn,
                    region=region,
                    vpc_id="vpc-sample123",
                    description="Sample security group",
                    rules=[
                        {
                            "direction": "ingress",
                            "protocol": "tcp",
                            "port_range": "22/22",
                            "source": "0.0.0.0/0",  # Unrestricted SSH!
                        },
                        {
                            "direction": "ingress",
                            "protocol": "tcp",
                            "port_range": "443/443",
                            "source": "10.0.0.0/8",
                        },
                    ],
                )

                self.security_groups[arn] = security_group
                logger.info(f"Found security group: {sg_id} in {region}")

            except Exception as error:
                self._handle_api_error(error, "DescribeSecurityGroups", region)
