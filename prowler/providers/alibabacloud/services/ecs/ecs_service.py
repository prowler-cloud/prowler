from datetime import datetime
from typing import Optional

from alibabacloud_ecs20140526 import models as ecs_models
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class ECS(AlibabaCloudService):
    """
    ECS (Elastic Compute Service) service class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud ECS service
    to retrieve instances, security groups, etc.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        super().__init__(__class__.__name__, provider, global_service=False)

        # Fetch ECS resources
        self.instances = []
        self.__threading_call__(self._describe_instances)
        self.security_groups = {}
        self.__threading_call__(self._describe_security_groups)
        self.disks = []
        self.__threading_call__(self._describe_disks)

    def _describe_instances(self, regional_client):
        """List all ECS instances in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ECS - Describing Instances in {region}...")

        try:
            request = ecs_models.DescribeInstancesRequest()
            request.region_id = region
            # Get all instances (paginated)
            page_number = 1
            page_size = 50

            while True:
                request.page_number = page_number
                request.page_size = page_size
                response = regional_client.describe_instances(request)

                if response and response.body and response.body.instances:
                    instances_data = response.body.instances.instance
                    if not instances_data:
                        break

                    for instance_data in instances_data:
                        instance_id = instance_data.instance_id
                        if not self.audit_resources or is_resource_filtered(
                            instance_id, self.audit_resources
                        ):
                            # Check network type
                            # InstanceNetworkType can be "classic" or "vpc"
                            # If VpcAttributes exists, it's VPC; if not, it might be classic
                            network_type = "vpc"  # Default to VPC
                            vpc_attributes = getattr(
                                instance_data, "vpc_attributes", None
                            )
                            instance_network_type = getattr(
                                instance_data, "instance_network_type", None
                            )

                            # Determine network type
                            if instance_network_type:
                                network_type = instance_network_type
                            elif not vpc_attributes:
                                # If no VPC attributes, it's likely classic network
                                network_type = "classic"

                            vpc_id = ""
                            if vpc_attributes:
                                vpc_id = getattr(vpc_attributes, "vpc_id", "")

                            self.instances.append(
                                Instance(
                                    id=instance_id,
                                    name=getattr(
                                        instance_data, "instance_name", instance_id
                                    ),
                                    region=region,
                                    status=getattr(instance_data, "status", ""),
                                    instance_type=getattr(
                                        instance_data, "instance_type", ""
                                    ),
                                    network_type=network_type,
                                    vpc_id=vpc_id,
                                    create_time=getattr(
                                        instance_data, "creation_time", None
                                    ),
                                )
                            )

                    # Check if there are more pages
                    total_count = getattr(response.body, "total_count", 0)
                    if page_number * page_size >= total_count:
                        break
                    page_number += 1
                else:
                    break

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_security_groups(self, regional_client):
        """List all security groups and their rules in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ECS - Describing Security Groups in {region}...")

        try:
            request = ecs_models.DescribeSecurityGroupsRequest()
            request.region_id = region
            # Get all security groups (paginated)
            page_number = 1
            page_size = 50

            while True:
                request.page_number = page_number
                request.page_size = page_size
                response = regional_client.describe_security_groups(request)

                if response and response.body and response.body.security_groups:
                    security_groups_data = response.body.security_groups.security_group
                    if not security_groups_data:
                        break

                    for sg_data in security_groups_data:
                        sg_id = sg_data.security_group_id
                        if not self.audit_resources or is_resource_filtered(
                            sg_id, self.audit_resources
                        ):
                            # Get security group rules
                            ingress_rules = []
                            egress_rules = []

                            # Get ingress rules
                            try:
                                rules_request = (
                                    ecs_models.DescribeSecurityGroupAttributeRequest()
                                )
                                rules_request.security_group_id = sg_id
                                rules_request.region_id = region
                                rules_request.direction = "ingress"
                                rules_response = (
                                    regional_client.describe_security_group_attribute(
                                        rules_request
                                    )
                                )

                                if (
                                    rules_response
                                    and rules_response.body
                                    and rules_response.body.permissions
                                ):
                                    permissions = (
                                        rules_response.body.permissions.permission
                                    )
                                    if permissions:
                                        for rule in permissions:
                                            ingress_rules.append(
                                                {
                                                    "port_range": getattr(
                                                        rule, "port_range", ""
                                                    ),
                                                    "source_cidr_ip": getattr(
                                                        rule, "source_cidr_ip", ""
                                                    ),
                                                    "ip_protocol": getattr(
                                                        rule, "ip_protocol", ""
                                                    ),
                                                    "policy": getattr(
                                                        rule, "policy", "accept"
                                                    ),
                                                }
                                            )
                            except Exception as error:
                                logger.warning(
                                    f"Could not get ingress rules for security group {sg_id}: {error}"
                                )

                            # Get egress rules
                            try:
                                rules_request = (
                                    ecs_models.DescribeSecurityGroupAttributeRequest()
                                )
                                rules_request.security_group_id = sg_id
                                rules_request.region_id = region
                                rules_request.direction = "egress"
                                rules_response = (
                                    regional_client.describe_security_group_attribute(
                                        rules_request
                                    )
                                )

                                if (
                                    rules_response
                                    and rules_response.body
                                    and rules_response.body.permissions
                                ):
                                    permissions = (
                                        rules_response.body.permissions.permission
                                    )
                                    if permissions:
                                        for rule in permissions:
                                            egress_rules.append(
                                                {
                                                    "port_range": getattr(
                                                        rule, "port_range", ""
                                                    ),
                                                    "dest_cidr_ip": getattr(
                                                        rule, "dest_cidr_ip", ""
                                                    ),
                                                    "ip_protocol": getattr(
                                                        rule, "ip_protocol", ""
                                                    ),
                                                    "policy": getattr(
                                                        rule, "policy", "accept"
                                                    ),
                                                }
                                            )
                            except Exception as error:
                                logger.warning(
                                    f"Could not get egress rules for security group {sg_id}: {error}"
                                )

                            sg_arn = f"acs:ecs:{region}:{self.audited_account}:security-group/{sg_id}"
                            self.security_groups[sg_arn] = SecurityGroup(
                                id=sg_id,
                                name=getattr(sg_data, "security_group_name", sg_id),
                                region=region,
                                arn=sg_arn,
                                vpc_id=getattr(sg_data, "vpc_id", ""),
                                description=getattr(sg_data, "description", ""),
                                ingress_rules=ingress_rules,
                                egress_rules=egress_rules,
                            )

                    # Check if there are more pages
                    total_count = getattr(response.body, "total_count", 0)
                    if page_number * page_size >= total_count:
                        break
                    page_number += 1
                else:
                    break

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_disks(self, regional_client):
        """List all disks in the region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"ECS - Describing Disks in {region}...")

        try:
            request = ecs_models.DescribeDisksRequest()
            request.region_id = region
            # Get all disks (paginated)
            page_number = 1
            page_size = 50

            while True:
                request.page_number = page_number
                request.page_size = page_size
                response = regional_client.describe_disks(request)

                if response and response.body and response.body.disks:
                    disks_data = response.body.disks.disk
                    if not disks_data:
                        break

                    for disk_data in disks_data:
                        disk_id = disk_data.disk_id
                        if not self.audit_resources or is_resource_filtered(
                            disk_id, self.audit_resources
                        ):
                            # Check if disk is attached
                            attached_instance_id = getattr(disk_data, "instance_id", "")
                            is_attached = bool(attached_instance_id)

                            # Check encryption status
                            # In Alibaba Cloud, encryption can be indicated by:
                            # 1. encrypted field (boolean)
                            # 2. encryption_algorithm field (non-empty string)
                            # 3. kms_key_id field (non-empty string)
                            encrypted = getattr(disk_data, "encrypted", False)
                            encryption_algorithm = getattr(
                                disk_data, "encryption_algorithm", ""
                            )
                            kms_key_id = getattr(disk_data, "kms_key_id", "")

                            # Disk is encrypted if any of these conditions are true
                            is_encrypted = (
                                encrypted
                                or bool(encryption_algorithm)
                                or bool(kms_key_id)
                            )

                            self.disks.append(
                                Disk(
                                    id=disk_id,
                                    name=getattr(disk_data, "disk_name", disk_id),
                                    region=region,
                                    status=getattr(disk_data, "status", ""),
                                    disk_category=getattr(disk_data, "category", ""),
                                    size=getattr(disk_data, "size", 0),
                                    is_attached=is_attached,
                                    attached_instance_id=attached_instance_id,
                                    is_encrypted=is_encrypted,
                                    encryption_algorithm=encryption_algorithm or "",
                                    create_time=getattr(
                                        disk_data, "creation_time", None
                                    ),
                                )
                            )

                    # Check if there are more pages
                    total_count = getattr(response.body, "total_count", 0)
                    if page_number * page_size >= total_count:
                        break
                    page_number += 1
                else:
                    break

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


# Models for ECS service
class Instance(BaseModel):
    """ECS Instance model."""

    id: str
    name: str
    region: str
    status: str
    instance_type: str
    network_type: str  # "classic" or "vpc"
    vpc_id: str = ""
    create_time: Optional[datetime] = None


class SecurityGroup(BaseModel):
    """ECS Security Group model."""

    id: str
    name: str
    region: str
    arn: str
    vpc_id: str = ""
    description: str = ""
    ingress_rules: list[dict] = []
    egress_rules: list[dict] = []


class Disk(BaseModel):
    """ECS Disk model."""

    id: str
    name: str
    region: str
    status: str
    disk_category: str
    size: int
    is_attached: bool
    attached_instance_id: str = ""
    is_encrypted: bool
    encryption_algorithm: str = ""
    create_time: Optional[datetime] = None
