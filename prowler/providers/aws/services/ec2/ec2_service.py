import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## EC2
class EC2:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_partition = audit_info.audited_partition
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.instances = []
        self.__threading_call__(self.__describe_instances__)
        self.__get_instance_user_data__()
        self.security_groups = []
        self.__threading_call__(self.__describe_security_groups__)
        self.network_acls = []
        self.__threading_call__(self.__describe_network_acls__)
        self.snapshots = []
        self.__threading_call__(self.__describe_snapshots__)
        self.__get_snapshot_public__()
        self.__threading_call__(self.__describe_network_interfaces__)
        self.images = []
        self.__threading_call__(self.__describe_images__)
        self.volumes = []
        self.__threading_call__(self.__describe_volumes__)
        self.ebs_encryption_by_default = []
        self.__threading_call__(self.__get_ebs_encryption_by_default__)
        self.elastic_ips = []
        self.__threading_call__(self.__describe_addresses__)

    def __get_session__(self):
        return self.session

    def __threading_call__(self, call):
        threads = []
        for regional_client in self.regional_clients.values():
            threads.append(threading.Thread(target=call, args=(regional_client,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __describe_instances__(self, regional_client):
        logger.info("EC2 - Describing EC2 Instances...")
        try:
            describe_instances_paginator = regional_client.get_paginator(
                "describe_instances"
            )
            for page in describe_instances_paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        http_tokens = None
                        http_endpoint = None
                        public_dns = None
                        public_ip = None
                        instance_profile = None
                        if "MetadataOptions" in instance:
                            http_tokens = instance["MetadataOptions"]["HttpTokens"]
                            http_endpoint = instance["MetadataOptions"]["HttpEndpoint"]
                        if (
                            "PublicDnsName" in instance
                            and "PublicIpAddress" in instance
                        ):
                            public_dns = instance["PublicDnsName"]
                            public_ip = instance["PublicIpAddress"]
                        if "IamInstanceProfile" in instance:
                            instance_profile = instance["IamInstanceProfile"]

                        self.instances.append(
                            Instance(
                                instance["InstanceId"],
                                instance["State"]["Name"],
                                regional_client.region,
                                instance["InstanceType"],
                                instance["ImageId"],
                                instance["LaunchTime"],
                                instance["PrivateDnsName"],
                                instance["PrivateIpAddress"],
                                public_dns,
                                public_ip,
                                http_tokens,
                                http_endpoint,
                                instance_profile,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_security_groups__(self, regional_client):
        logger.info("EC2 - Describing Security Groups...")
        try:
            describe_security_groups_paginator = regional_client.get_paginator(
                "describe_security_groups"
            )
            for page in describe_security_groups_paginator.paginate():
                for sg in page["SecurityGroups"]:
                    self.security_groups.append(
                        SecurityGroup(
                            sg["GroupName"],
                            regional_client.region,
                            sg["GroupId"],
                            sg["IpPermissions"],
                            sg["IpPermissionsEgress"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_network_acls__(self, regional_client):
        logger.info("EC2 - Describing Network ACLs...")
        try:
            describe_network_acls_paginator = regional_client.get_paginator(
                "describe_network_acls"
            )
            for page in describe_network_acls_paginator.paginate():
                for nacl in page["NetworkAcls"]:
                    self.network_acls.append(
                        NetworkACL(
                            nacl["NetworkAclId"],
                            regional_client.region,
                            nacl["Entries"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_snapshots__(self, regional_client):
        logger.info("EC2 - Describing Snapshots...")
        try:
            describe_snapshots_paginator = regional_client.get_paginator(
                "describe_snapshots"
            )
            encrypted = False
            for page in describe_snapshots_paginator.paginate(OwnerIds=["self"]):
                for snapshot in page["Snapshots"]:
                    if snapshot["Encrypted"]:
                        encrypted = True
                    self.snapshots.append(
                        Snapshot(
                            snapshot["SnapshotId"], regional_client.region, encrypted
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_snapshot_public__(self):
        logger.info("EC2 - Gettting snapshots encryption...")
        try:
            for snapshot in self.snapshots:
                regional_client = self.regional_clients[snapshot.region]
                snapshot_public = regional_client.describe_snapshot_attribute(
                    Attribute="createVolumePermission", SnapshotId=snapshot.id
                )
                for permission in snapshot_public["CreateVolumePermissions"]:
                    if "Group" in permission:
                        if permission["Group"] == "all":
                            snapshot.public = True
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_network_interfaces__(self, regional_client):
        logger.info("EC2 - Describing Network Interfaces...")
        try:
            # Get SGs Network Interfaces
            for sg in self.security_groups:
                regional_client = self.regional_clients[sg.region]
                describe_network_interfaces_paginator = regional_client.get_paginator(
                    "describe_network_interfaces"
                )
                for page in describe_network_interfaces_paginator.paginate(
                    Filters=[
                        {
                            "Name": "group-id",
                            "Values": [
                                sg.id,
                            ],
                        },
                    ],
                ):
                    for interface in page["NetworkInterfaces"]:
                        sg.network_interfaces.append(interface["NetworkInterfaceId"])

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_instance_user_data__(self):
        logger.info("EC2 - Gettting instance user data...")
        try:
            for instance in self.instances:
                regional_client = self.regional_clients[instance.region]
                user_data = regional_client.describe_instance_attribute(
                    Attribute="userData", InstanceId=instance.id
                )["UserData"]
                if "Value" in user_data:
                    instance.user_data = user_data["Value"]
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_images__(self, regional_client):
        logger.info("EC2 - Describing Images...")
        try:
            public = False
            for image in regional_client.describe_images(Owners=["self"])["Images"]:
                if image["Public"]:
                    public = True
                self.images.append(
                    Image(
                        image["ImageId"], image["Name"], public, regional_client.region
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_volumes__(self, regional_client):
        logger.info("EC2 - Describing Volumes...")
        try:
            describe_volumes_paginator = regional_client.get_paginator(
                "describe_volumes"
            )
            for page in describe_volumes_paginator.paginate():
                for volume in page["Volumes"]:
                    self.volumes.append(
                        Volume(
                            volume["VolumeId"],
                            regional_client.region,
                            volume["Encrypted"],
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_addresses__(self, regional_client):
        logger.info("EC2 - Describing Elastic IPs...")
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

                self.elastic_ips.append(
                    ElasticIP(
                        public_ip,
                        association_id,
                        allocation_id,
                        elastic_ip_arn,
                        regional_client.region,
                    )
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_ebs_encryption_by_default__(self, regional_client):
        logger.info("EC2 - Get EBS Encryption By Default...")
        try:
            self.ebs_encryption_by_default.append(
                EbsEncryptionByDefault(
                    regional_client.get_ebs_encryption_by_default()[
                        "EbsEncryptionByDefault"
                    ],
                    regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


@dataclass
class Instance:
    id: str
    state: str
    region: str
    type: str
    image_id: str
    launch_time: str
    private_dns: str
    private_ip: str
    public_dns: str
    public_ip: str
    user_data: str
    http_tokens: str
    http_endpoint: str
    instance_profile: str

    def __init__(
        self,
        id,
        state,
        region,
        type,
        image_id,
        launch_time,
        private_dns,
        private_ip,
        public_dns,
        public_ip,
        http_tokens,
        http_endpoint,
        instance_profile,
    ):
        self.id = id
        self.state = state
        self.region = region
        self.type = type
        self.image_id = image_id
        self.launch_time = launch_time
        self.private_dns = private_dns
        self.private_ip = private_ip
        self.public_dns = public_dns
        self.public_ip = public_ip
        self.http_tokens = http_tokens
        self.http_endpoint = http_endpoint
        self.user_data = None
        self.instance_profile = instance_profile


@dataclass
class Snapshot:
    id: str
    region: str
    encrypted: bool
    public: bool

    def __init__(self, id, region, encrypted):
        self.id = id
        self.region = region
        self.encrypted = encrypted
        self.public = False


@dataclass
class Volume:
    id: str
    region: str
    encrypted: bool

    def __init__(self, id, region, encrypted):
        self.id = id
        self.region = region
        self.encrypted = encrypted


@dataclass
class SecurityGroup:
    name: str
    region: str
    id: str
    network_interfaces: list[str]
    ingress_rules: list[dict]
    egress_rules: list[dict]

    def __init__(self, name, region, id, ingress_rules, egress_rules):
        self.name = name
        self.region = region
        self.id = id
        self.ingress_rules = ingress_rules
        self.egress_rules = egress_rules
        self.network_interfaces = []


@dataclass
class NetworkACL:
    id: str
    region: str
    entries: list[dict]

    def __init__(self, id, region, entries):
        self.id = id
        self.region = region
        self.entries = entries


@dataclass
class ElasticIP:
    public_ip: str
    association_id: str
    arn: str
    allocation_id: str
    region: str

    def __init__(self, public_ip, association_id, allocation_id, arn, region):
        self.public_ip = public_ip
        self.association_id = association_id
        self.allocation_id = allocation_id
        self.arn = arn
        self.region = region


@dataclass
class Image:
    id: str
    name: str
    public: bool
    region: str

    def __init__(self, id, name, public, region):
        self.id = id
        self.name = name
        self.public = public
        self.region = region


@dataclass
class EbsEncryptionByDefault:
    status: bool
    region: str

    def __init__(self, status, region):
        self.status = status
        self.region = region
