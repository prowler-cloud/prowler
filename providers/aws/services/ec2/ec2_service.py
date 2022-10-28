import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## EC2
class EC2:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.instances = []
        self.__threading_call__(self.__describe_instances__)
        self.security_groups = []
        self.__threading_call__(self.__describe_security_groups__)
        self.network_acls = []
        self.__threading_call__(self.__describe_network_acls__)
        self.snapshots = []
        self.__threading_call__(self.__describe_snapshots__)
        self.__get_snapshot_public__()
        self.elastic_ips = []
        self.__threading_call__(self.__describe_elastic_ips__)

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
                        if (
                            "PublicDnsName" in instance
                            and "PublicIpAddress" in instance
                        ):
                            self.instances.append(
                                Instance(
                                    instance["InstanceId"],
                                    regional_client.region,
                                    instance["InstanceType"],
                                    instance["ImageId"],
                                    instance["LaunchTime"],
                                    instance["PrivateDnsName"],
                                    instance["PrivateIpAddress"],
                                    instance["PublicDnsName"],
                                    instance["PublicIpAddress"],
                                )
                            )
                        else:
                            self.instances.append(
                                Instance(
                                    instance["InstanceId"],
                                    regional_client.region,
                                    instance["InstanceType"],
                                    instance["ImageId"],
                                    instance["LaunchTime"],
                                    instance["PrivateDnsName"],
                                    instance["PrivateIpAddress"],
                                    None,
                                    None,
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
            for page in describe_snapshots_paginator.paginate(
                OwnerIds=[str(self.audited_account)]
            ):
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
        logger.info("EC2 - Get snapshots encryption...")
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

    def __describe_elastic_ips__(self, regional_client):
        logger.info("EC2 - Describing Security Groups...")
        try:
            describe_network_interfaces_paginator = regional_client.get_paginator(
                "describe_network_interfaces"
            )
            for page in describe_network_interfaces_paginator.paginate():
                for eip in page["NetworkInterfaces"]:
                    # Get only public attached ones
                    if "Association" in eip:
                        self.elastic_ips.append(
                            ElasticIP(
                                eip["Association"]["PublicIp"],
                                eip["VpcId"],
                                eip["SubnetId"],
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
    region: str
    type: str
    image_id: str
    launch_time: str
    private_dns: str
    private_ip: str
    public_dns: str
    public_ip: str

    def __init__(
        self,
        id,
        region,
        type,
        image_id,
        launch_time,
        private_dns,
        private_ip,
        public_dns,
        public_ip,
    ):
        self.id = id
        self.region = region
        self.type = type
        self.image_id = image_id
        self.launch_time = launch_time
        self.private_dns = private_dns
        self.private_ip = private_ip
        self.public_dns = public_dns
        self.public_ip = public_ip


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
class SecurityGroup:
    name: str
    region: str
    id: str
    ingress_rules: list[dict]
    egress_rules: list[dict]

    def __init__(self, name, region, id, ingress_rules, egress_rules):
        self.name = name
        self.region = region
        self.id = id
        self.ingress_rules = ingress_rules
        self.egress_rules = egress_rules


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
    vpc: str
    subnet: str
    region: str

    def __init__(self, public_ip, vpc, subnet, region):
        self.public_ip = public_ip
        self.vpc = vpc
        self.subnet = subnet
        self.region = region
