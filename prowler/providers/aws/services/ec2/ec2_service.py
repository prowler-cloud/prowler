from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Optional, Union

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


################## EC2
class EC2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.account_arn_template = f"arn:{self.audited_partition}:ec2:{self.region}:{self.audited_account}:account"
        self.instances = []
        self.__threading_call__(self._describe_instances)
        self.__threading_call__(self._get_instance_user_data, self.instances)
        self.security_groups = {}
        self.regions_with_sgs = []
        self.__threading_call__(self._describe_security_groups)
        self.network_acls = {}
        self.__threading_call__(self._describe_network_acls)
        self.snapshots = []
        self.volumes_with_snapshots = {}
        self.regions_with_snapshots = {}
        self.__threading_call__(self._describe_snapshots)
        self.__threading_call__(self._determine_public_snapshots, self.snapshots)
        self.network_interfaces = {}
        self.__threading_call__(self._describe_network_interfaces)
        self.images = []
        self.__threading_call__(self._describe_images)
        self.volumes = []
        self.__threading_call__(self._describe_volumes)
        self.attributes_for_regions = {}
        self.__threading_call__(self._get_resources_for_regions)
        self.ebs_encryption_by_default = []
        self.__threading_call__(self._get_ebs_encryption_settings)
        self.elastic_ips = []
        self.__threading_call__(self._describe_ec2_addresses)
        self.ebs_block_public_access_snapshots_states = []
        self.__threading_call__(self._get_snapshot_block_public_access_state)
        self.instance_metadata_defaults = []
        self.__threading_call__(self._get_instance_metadata_defaults)
        self.launch_templates = []
        self.__threading_call__(self._describe_launch_templates)
        self.__threading_call__(
            self._describe_launch_template_versions, self.launch_templates
        )
        self.vpn_endpoints = {}
        self.__threading_call__(self._describe_vpn_endpoints)
        self.transit_gateways = {}
        self.__threading_call__(self._describe_transit_gateways)

    def _get_volume_arn_template(self, region):
        return (
            f"arn:{self.audited_partition}:ec2:{region}:{self.audited_account}:volume"
        )

    def _describe_instances(self, regional_client):
        try:
            describe_instances_paginator = regional_client.get_paginator(
                "describe_instances"
            )
            for page in describe_instances_paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:instance/{instance['InstanceId']}"
                        if not self.audit_resources or (
                            is_resource_filtered(arn, self.audit_resources)
                        ):
                            enis = []
                            for eni in instance.get("NetworkInterfaces", []):
                                network_interface_id = eni.get("NetworkInterfaceId")
                                if network_interface_id:
                                    enis.append(network_interface_id)
                            self.instances.append(
                                Instance(
                                    id=instance["InstanceId"],
                                    arn=arn,
                                    state=instance["State"]["Name"],
                                    region=regional_client.region,
                                    type=instance["InstanceType"],
                                    image_id=instance["ImageId"],
                                    launch_time=instance["LaunchTime"],
                                    private_dns=instance["PrivateDnsName"],
                                    private_ip=instance.get("PrivateIpAddress"),
                                    public_dns=instance.get("PublicDnsName"),
                                    public_ip=instance.get("PublicIpAddress"),
                                    http_tokens=instance.get("MetadataOptions", {}).get(
                                        "HttpTokens"
                                    ),
                                    http_endpoint=instance.get(
                                        "MetadataOptions", {}
                                    ).get("HttpEndpoint"),
                                    instance_profile=instance.get("IamInstanceProfile"),
                                    monitoring_state=instance.get(
                                        "Monitoring", {"State": "disabled"}
                                    ).get("State", "disabled"),
                                    security_groups=[
                                        sg["GroupId"]
                                        for sg in instance.get("SecurityGroups", [])
                                    ],
                                    subnet_id=instance.get("SubnetId", ""),
                                    network_interfaces=enis,
                                    virtualization_type=instance.get(
                                        "VirtualizationType"
                                    ),
                                    tags=instance.get("Tags"),
                                )
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_security_groups(self, regional_client):
        try:
            describe_security_groups_paginator = regional_client.get_paginator(
                "describe_security_groups"
            )
            for page in describe_security_groups_paginator.paginate():
                for sg in page["SecurityGroups"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:security-group/{sg['GroupId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        associated_sgs = []
                        for ingress_rule in sg["IpPermissions"]:
                            # check associated security groups
                            for sg_group in ingress_rule.get("UserIdGroupPairs", []):
                                if sg_group.get("GroupId"):
                                    associated_sgs.append(sg_group["GroupId"])
                        self.security_groups[arn] = SecurityGroup(
                            name=sg["GroupName"],
                            region=regional_client.region,
                            id=sg["GroupId"],
                            ingress_rules=sg["IpPermissions"],
                            egress_rules=sg["IpPermissionsEgress"],
                            associated_sgs=associated_sgs,
                            vpc_id=sg["VpcId"],
                            tags=sg.get("Tags"),
                        )
                        if sg["GroupName"] != "default":
                            self.regions_with_sgs.append(regional_client.region)
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_network_acls(self, regional_client):
        try:
            describe_network_acls_paginator = regional_client.get_paginator(
                "describe_network_acls"
            )
            for page in describe_network_acls_paginator.paginate():
                for nacl in page["NetworkAcls"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:network-acl/{nacl['NetworkAclId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        nacl_name = ""
                        for tag in nacl.get("Tags", []):
                            if tag["Key"] == "Name":
                                nacl_name = tag["Value"]
                        in_use = False
                        for subnet in nacl["Associations"]:
                            if subnet["SubnetId"]:
                                in_use = True
                                break
                        self.network_acls[arn] = NetworkACL(
                            id=nacl["NetworkAclId"],
                            arn=arn,
                            name=nacl_name,
                            region=regional_client.region,
                            entries=nacl["Entries"],
                            tags=nacl.get("Tags"),
                            in_use=in_use,
                            default=nacl["IsDefault"],
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_snapshots(self, regional_client):
        try:
            snapshots_in_region = False
            describe_snapshots_paginator = regional_client.get_paginator(
                "describe_snapshots"
            )
            for page in describe_snapshots_paginator.paginate(OwnerIds=["self"]):
                for snapshot in page["Snapshots"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:snapshot/{snapshot['SnapshotId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        if snapshots_in_region is False:
                            snapshots_in_region = True
                        self.snapshots.append(
                            Snapshot(
                                id=snapshot["SnapshotId"],
                                arn=arn,
                                region=regional_client.region,
                                encrypted=snapshot.get("Encrypted", False),
                                tags=snapshot.get("Tags"),
                                volume=snapshot["VolumeId"],
                            )
                        )
                        # Store that the volume has at least one snapshot
                        self.volumes_with_snapshots[snapshot["VolumeId"]] = True
            # Store that the region has at least one snapshot
            self.regions_with_snapshots[regional_client.region] = snapshots_in_region
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _determine_public_snapshots(self, snapshot):
        try:
            regional_client = self.regional_clients[snapshot.region]
            snapshot_public = regional_client.describe_snapshot_attribute(
                Attribute="createVolumePermission", SnapshotId=snapshot.id
            )
            for permission in snapshot_public["CreateVolumePermissions"]:
                if "Group" in permission:
                    if permission["Group"] == "all":
                        snapshot.public = True

        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidSnapshot.NotFound":
                logger.warning(
                    f"{snapshot.region} --"
                    f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                    f" {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_network_interfaces(self, regional_client):
        try:
            # Get Network Interfaces with Public IPs
            describe_network_interfaces_paginator = regional_client.get_paginator(
                "describe_network_interfaces"
            )
            for page in describe_network_interfaces_paginator.paginate():
                for interface in page["NetworkInterfaces"]:
                    id = interface["NetworkInterfaceId"]
                    public_ip_addresses = []

                    # Check for public IPs in the 'PrivateIpAddresses' block
                    for private_ip_info in interface.get("PrivateIpAddresses", []):
                        private_association = private_ip_info.get("Association", {})
                        public_ip_str = private_association.get("PublicIp")
                        if public_ip_str:
                            public_ip = ip_address(public_ip_str)
                            if public_ip.is_global:
                                public_ip_addresses.append(public_ip)

                        private_ip_str = private_ip_info.get("PrivateIpAddress")
                        if private_ip_str:
                            private_ip = ip_address(private_ip_str)
                            if private_ip.is_global:
                                public_ip_addresses.append(private_ip)

                    # Check for public IPs in the 'IPv6Addresses' block
                    for ipv6_info in interface.get("Ipv6Addresses", []):
                        ipv6_address_str = ipv6_info.get("Ipv6Address")
                        if ipv6_address_str:
                            ipv6_address = ip_address(ipv6_address_str)
                            if ipv6_address.is_global:
                                public_ip_addresses.append(ipv6_address)
                    attachment = Attachment(
                        attachment_id=interface.get("Attachment", {}).get(
                            "AttachmentId", ""
                        ),
                        instance_id=interface.get("Attachment", {}).get(
                            "InstanceId", ""
                        ),
                        instance_owner_id=interface.get("Attachment", {}).get(
                            "InstanceOwnerId", ""
                        ),
                        status=interface.get("Attachment", {}).get("Status", ""),
                    )
                    self.network_interfaces[id] = NetworkInterface(
                        id=id,
                        association=interface.get("Association", {}),
                        attachment=attachment,
                        private_ip=interface.get("PrivateIpAddress"),
                        type=interface["InterfaceType"],
                        subnet_id=interface["SubnetId"],
                        vpc_id=interface["VpcId"],
                        region=regional_client.region,
                        tags=interface.get("TagSet"),
                        public_ip_addresses=public_ip_addresses,
                    )
                    # Add Network Interface to Security Group
                    # 'Groups': [
                    #     {
                    #         'GroupId': 'sg-xxxxx',
                    #         'GroupName': 'default',
                    #     },
                    # ],
                    self._add_network_interfaces_to_security_groups(
                        self.network_interfaces[id], interface.get("Groups", [])
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _add_network_interfaces_to_security_groups(
        self, interface, interface_security_groups
    ):
        try:
            for sg in interface_security_groups:
                for security_group in self.security_groups.values():
                    if security_group.id == sg["GroupId"]:
                        security_group.network_interfaces.append(interface)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_instance_user_data(self, instance):
        try:
            regional_client = self.regional_clients[instance.region]
            user_data = regional_client.describe_instance_attribute(
                Attribute="userData", InstanceId=instance.id
            )["UserData"]
            if "Value" in user_data:
                instance.user_data = user_data["Value"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_images(self, regional_client):
        try:
            for image in regional_client.describe_images(Owners=["self"])["Images"]:
                arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:image/{image['ImageId']}"
                if not self.audit_resources or (
                    is_resource_filtered(arn, self.audit_resources)
                ):
                    self.images.append(
                        Image(
                            id=image["ImageId"],
                            arn=arn,
                            name=image.get("Name", ""),
                            public=image.get("Public", False),
                            region=regional_client.region,
                            tags=image.get("Tags"),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_volumes(self, regional_client):
        try:
            describe_volumes_paginator = regional_client.get_paginator(
                "describe_volumes"
            )
            for page in describe_volumes_paginator.paginate():
                for volume in page["Volumes"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:volume/{volume['VolumeId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.volumes.append(
                            Volume(
                                id=volume["VolumeId"],
                                arn=arn,
                                region=regional_client.region,
                                encrypted=volume["Encrypted"],
                                tags=volume.get("Tags"),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_ec2_addresses(self, regional_client):
        try:
            for address in regional_client.describe_addresses()["Addresses"]:
                public_ip = None
                association_id = None
                allocation_id = None
                if "PublicIp" in address:
                    public_ip = address["PublicIp"]
                if "AssociationId" in address:
                    association_id = address["AssociationId"]
                if "AllocationId" in address:
                    allocation_id = address["AllocationId"]
                elastic_ip_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:eip-allocation/{allocation_id}"
                if not self.audit_resources or (
                    is_resource_filtered(elastic_ip_arn, self.audit_resources)
                ):
                    self.elastic_ips.append(
                        ElasticIP(
                            public_ip=public_ip,
                            association_id=association_id,
                            allocation_id=allocation_id,
                            arn=elastic_ip_arn,
                            region=regional_client.region,
                            tags=address.get("Tags"),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_ebs_encryption_settings(self, regional_client):
        try:
            volumes_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            volumes_in_region = volumes_in_region.get("has_volumes", False)
            self.ebs_encryption_by_default.append(
                EbsEncryptionByDefault(
                    status=regional_client.get_ebs_encryption_by_default()[
                        "EbsEncryptionByDefault"
                    ],
                    volumes=volumes_in_region,
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_snapshot_block_public_access_state(self, regional_client):
        try:
            snapshots_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            snapshots_in_region = snapshots_in_region.get("has_snapshots", False)
            self.ebs_block_public_access_snapshots_states.append(
                EbsSnapshotBlockPublicAccess(
                    status=regional_client.get_snapshot_block_public_access_state()[
                        "State"
                    ],
                    snapshots=snapshots_in_region,
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_instance_metadata_defaults(self, regional_client):
        try:
            instances_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            instances_in_region = instances_in_region.get("has_instances", False)
            metadata_defaults = regional_client.get_instance_metadata_defaults()
            account_level = metadata_defaults.get("AccountLevel", {})
            self.instance_metadata_defaults.append(
                InstanceMetadataDefaults(
                    http_tokens=account_level.get("HttpTokens", None),
                    instances=instances_in_region,
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_resources_for_regions(self, regional_client):
        try:
            has_instances = False
            for instance in self.instances:
                if instance.region == regional_client.region:
                    has_instances = True
                    break
            has_snapshots = False
            for snapshot in self.snapshots:
                if snapshot.region == regional_client.region:
                    has_snapshots = True
                    break
            has_volumes = False
            for volume in self.volumes:
                if volume.region == regional_client.region:
                    has_volumes = True
                    break
            self.attributes_for_regions[regional_client.region] = {
                "has_instances": has_instances,
                "has_snapshots": has_snapshots,
                "has_volumes": has_volumes,
            }
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_launch_templates(self, regional_client):
        try:
            describe_launch_templates_paginator = regional_client.get_paginator(
                "describe_launch_templates"
            )

            for page in describe_launch_templates_paginator.paginate():
                for template in page["LaunchTemplates"]:
                    template_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:launch-template/{template['LaunchTemplateId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(template_arn, self.audit_resources)
                    ):
                        self.launch_templates.append(
                            LaunchTemplate(
                                name=template["LaunchTemplateName"],
                                id=template["LaunchTemplateId"],
                                arn=template_arn,
                                region=regional_client.region,
                                versions=[],
                                tags=template.get("Tags"),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_launch_template_versions(self, launch_template):
        try:
            regional_client = self.regional_clients[launch_template.region]
            describe_launch_template_versions_paginator = regional_client.get_paginator(
                "describe_launch_template_versions"
            )

            for page in describe_launch_template_versions_paginator.paginate(
                LaunchTemplateId=launch_template.id
            ):
                for template_version in page["LaunchTemplateVersions"]:
                    enis = []
                    associate_public_ip = False
                    for eni in template_version["LaunchTemplateData"].get(
                        "NetworkInterfaces", []
                    ):
                        network_interface_id = eni.get("NetworkInterfaceId", "")
                        if network_interface_id in self.network_interfaces:
                            enis.append(self.network_interfaces[network_interface_id])
                        if eni.get("AssociatePublicIpAddress", False):
                            associate_public_ip = True
                    launch_template.versions.append(
                        LaunchTemplateVersion(
                            version_number=template_version["VersionNumber"],
                            template_data=TemplateData(
                                user_data=template_version["LaunchTemplateData"].get(
                                    "UserData", ""
                                ),
                                network_interfaces=enis,
                                associate_public_ip_address=associate_public_ip,
                            ),
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_vpn_endpoints(self, regional_client):
        try:
            describe_client_vpn_endpoints_paginator = regional_client.get_paginator(
                "describe_client_vpn_endpoints"
            )

            for page in describe_client_vpn_endpoints_paginator.paginate():
                for vpn_endpoint in page["ClientVpnEndpoints"]:
                    vpn_endpoint_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:client-vpn-endpoint/{vpn_endpoint['ClientVpnEndpointId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(vpn_endpoint_arn, self.audit_resources)
                    ):
                        self.vpn_endpoints[vpn_endpoint_arn] = VpnEndpoint(
                            id=vpn_endpoint["ClientVpnEndpointId"],
                            arn=vpn_endpoint_arn,
                            connection_logging=vpn_endpoint["ConnectionLogOptions"][
                                "Enabled"
                            ],
                            region=regional_client.region,
                            tags=vpn_endpoint.get("Tags"),
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_transit_gateways(self, regional_client):
        try:
            describe_transit_gateways_paginator = regional_client.get_paginator(
                "describe_transit_gateways"
            )

            for page in describe_transit_gateways_paginator.paginate():
                for transit_gateway in page["TransitGateways"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            transit_gateway["TransitGatewayArn"], self.audit_resources
                        )
                    ):
                        self.transit_gateways[transit_gateway["TransitGatewayArn"]] = (
                            TransitGateway(
                                id=transit_gateway["TransitGatewayId"],
                                auto_accept_shared_attachments=(
                                    transit_gateway["Options"][
                                        "AutoAcceptSharedAttachments"
                                    ]
                                    == "enable"
                                ),
                                region=regional_client.region,
                                tags=transit_gateway.get("Tags"),
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Instance(BaseModel):
    id: str
    arn: str
    state: str
    region: str
    type: str
    image_id: str
    launch_time: datetime
    private_dns: str
    private_ip: Optional[str]
    public_dns: Optional[str]
    public_ip: Optional[str]
    user_data: Optional[str]
    http_tokens: Optional[str]
    http_endpoint: Optional[str]
    monitoring_state: str
    security_groups: list[str]
    subnet_id: str
    instance_profile: Optional[dict]
    network_interfaces: Optional[list]
    virtualization_type: Optional[str]
    tags: Optional[list] = []


class Snapshot(BaseModel):
    id: str
    arn: str
    region: str
    encrypted: bool
    public: bool = False
    tags: Optional[list] = []
    volume: Optional[str]


class Volume(BaseModel):
    id: str
    arn: str
    region: str
    encrypted: bool
    tags: Optional[list] = []


class Attachment(BaseModel):
    attachment_id: str = ""
    instance_id: str = ""
    instance_owner_id: str = ""
    status: str = ""


class NetworkInterface(BaseModel):
    id: str
    association: dict
    attachment: Attachment
    private_ip: Optional[str]
    public_ip_addresses: list[Union[IPv4Address, IPv6Address]]
    type: str
    subnet_id: str
    vpc_id: str
    region: str
    tags: Optional[list] = []


class SecurityGroup(BaseModel):
    name: str
    region: str
    id: str
    vpc_id: str
    associated_sgs: list
    network_interfaces: list[NetworkInterface] = []
    ingress_rules: list[dict]
    egress_rules: list[dict]
    tags: Optional[list] = []


class NetworkACL(BaseModel):
    id: str
    arn: str
    name: str
    region: str
    entries: list[dict]
    default: bool
    in_use: bool
    tags: Optional[list] = []


class ElasticIP(BaseModel):
    public_ip: Optional[str]
    association_id: Optional[str]
    arn: str
    allocation_id: Optional[str]
    region: str
    tags: Optional[list] = []


class Image(BaseModel):
    id: str
    arn: str
    name: str
    public: bool
    region: str
    tags: Optional[list] = []


class EbsEncryptionByDefault(BaseModel):
    status: bool
    volumes: bool
    region: str


class EbsSnapshotBlockPublicAccess(BaseModel):
    status: str
    snapshots: bool
    region: str


class InstanceMetadataDefaults(BaseModel):
    http_tokens: Optional[str]
    instances: bool
    region: str


class TemplateData(BaseModel):
    user_data: str
    network_interfaces: Optional[list[NetworkInterface]]
    associate_public_ip_address: Optional[bool]


class LaunchTemplateVersion(BaseModel):
    version_number: int
    template_data: TemplateData


class LaunchTemplate(BaseModel):
    name: str
    id: str
    arn: str
    region: str
    versions: list[LaunchTemplateVersion] = []
    tags: Optional[list] = []


class VpnEndpoint(BaseModel):
    id: str
    connection_logging: bool
    region: str
    tags: Optional[list] = []


class TransitGateway(BaseModel):
    id: str
    auto_accept_shared_attachments: bool
    region: str
    tags: Optional[list] = []
