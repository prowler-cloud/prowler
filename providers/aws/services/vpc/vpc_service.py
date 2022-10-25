import threading
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################## VPC
class VPC:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.vpcs = []
        self.vpc_peering_connections = []
        self.__threading_call__(self.__describe_vpcs__)
        self.__threading_call__(self.__describe_vpc_peering_connections__)
        self.__describe_flow_logs__()
        self.__describe_route_tables__()

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

    def __describe_vpcs__(self, regional_client):
        logger.info("VPC - Describing VPCs...")
        try:
            describe_vpcs_paginator = regional_client.get_paginator("describe_vpcs")
            for page in describe_vpcs_paginator.paginate():
                for vpc in page["Vpcs"]:
                    self.vpcs.append(
                        VPCs(
                            vpc["VpcId"],
                            vpc["IsDefault"],
                            vpc["CidrBlock"],
                            regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_vpc_peering_connections__(self, regional_client):
        logger.info("VPC - Describing VPC Peering Connections...")
        try:
            describe_vpc_peering_connections_paginator = regional_client.get_paginator(
                "describe_vpc_peering_connections"
            )
            for page in describe_vpc_peering_connections_paginator.paginate():
                for conn in page["VpcPeeringConnections"]:
                    self.vpc_peering_connections.append(
                        VpcPeeringConnection(
                            conn["VpcPeeringConnectionId"],
                            conn["AccepterVpcInfo"]["VpcId"],
                            conn["AccepterVpcInfo"]["CidrBlock"],
                            conn["RequesterVpcInfo"]["VpcId"],
                            conn["RequesterVpcInfo"]["CidrBlock"],
                            regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_route_tables__(self):
        logger.info("VPC - Describing Peering Route Tables...")
        try:
            for conn in self.vpc_peering_connections:
                regional_client = self.regional_clients[conn.region]
                for route_table in regional_client.describe_route_tables(
                    Filters=[
                        {
                            "Name": "route.vpc-peering-connection-id",
                            "Values": [
                                conn.id,
                            ],
                        },
                    ]
                )["RouteTables"]:
                    destination_cidrs = []
                    for route in route_table["Routes"]:
                        if (
                            route["Origin"] != "CreateRouteTable"
                        ):  # avoid default route table
                            destination_cidrs.append(route["DestinationCidrBlock"])
                    conn.route_tables.append(
                        Route(
                            route_table["RouteTableId"],
                            destination_cidrs,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}: {error}"
            )

    def __describe_flow_logs__(self):
        logger.info("VPC - Describing flow logs...")
        try:
            for vpc in self.vpcs:
                regional_client = self.regional_clients[vpc.region]
                flow_logs = regional_client.describe_flow_logs(
                    Filters=[
                        {
                            "Name": "resource-id",
                            "Values": [
                                vpc.id,
                            ],
                        },
                    ]
                )["FlowLogs"]
                if flow_logs:
                    vpc.flow_log = True
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")


@dataclass
class VPCs:
    id: str
    default: bool
    cidr_block: str
    flow_log: bool
    region: str

    def __init__(
        self,
        id,
        default,
        cidr_block,
        region,
    ):
        self.id = id
        self.default = default
        self.cidr_block = cidr_block
        self.flow_log = False
        self.region = region


@dataclass
class Route:
    id: str
    destination_cidrs: list[str]

    def __init__(
        self,
        id,
        destination_cidrs,
    ):
        self.id = id
        self.destination_cidrs = destination_cidrs


@dataclass
class VpcPeeringConnection:
    id: str
    accepter_vpc: str
    accepter_cidr: str
    requester_vpc: str
    requester_cidr: str
    route_tables: list[Route]
    region: str

    def __init__(
        self,
        id,
        accepter_vpc,
        accepter_cidr,
        requester_vpc,
        requester_cidr,
        region,
    ):
        self.id = id
        self.accepter_vpc = accepter_vpc
        self.accepter_cidr = accepter_cidr
        self.requester_vpc = requester_vpc
        self.requester_cidr = requester_cidr
        self.route_tables = []
        self.region = region
