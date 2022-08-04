import threading
from dataclasses import dataclass
from typing import Any

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info, generate_regional_clients


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
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
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
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_network_acls__(self, regional_client):
        logger.info("EC2 - Describing Security Groups...")
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
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_snapshots__(self, regional_client):
        logger.info("EC2 - Describing Snapshots...")
        try:
            describe_snapshots_paginator = regional_client.get_paginator(
                "describe_snapshots"
            )
            encrypted = False
            for page in describe_snapshots_paginator.paginate(
                OwnerIds=[self.audited_account]
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
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
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
            logger.error(f"{error.__class__.__name__}: {error}")


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
    entries: list[dict]

    def __init__(self, id, region, entries):
        self.id = id
        self.region = region
        self.entries = entries


ec2_client = EC2(current_audit_info)

################## Security Groups
# Check if the security group ingress rule has public access to the check_ports using the protocol
def check_security_group(ingress_rule: Any, protocol: str, ports: list = []) -> bool:
    public_IPv4 = "0.0.0.0/0"
    public_IPv6 = "::/0"

    # Check for all traffic ingress rules regardless of the protocol
    if ingress_rule["IpProtocol"] == "-1" and (
        (
            "0.0.0.0/0" in str(ingress_rule["IpRanges"])
            or "::/0" in str(ingress_rule["Ipv6Ranges"])
        )
    ):
        return True

    # Check for specific ports in ingress rules
    if "FromPort" in ingress_rule:
        # All ports
        if ingress_rule["FromPort"] == 0 and ingress_rule["ToPort"] == 65535:
            return True

        # If there is a port range
        if ingress_rule["FromPort"] != ingress_rule["ToPort"]:
            # Calculate port range, adding 1
            diff = (ingress_rule["ToPort"] - ingress_rule["FromPort"]) + 1
            ingress_port_range = []
            for x in range(diff):
                ingress_port_range.append(int(ingress_rule["FromPort"]) + x)
        # If FromPort and ToPort are the same
        else:
            ingress_port_range = []
            ingress_port_range.append(int(ingress_rule["FromPort"]))

        # Test Security Group
        for port in ports:
            if (
                (
                    public_IPv4 in str(ingress_rule["IpRanges"])
                    or public_IPv6 in str(ingress_rule["Ipv6Ranges"])
                )
                and port in ingress_port_range
                and ingress_rule["IpProtocol"] == protocol
            ):
                return True
    return False
