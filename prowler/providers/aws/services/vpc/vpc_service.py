import json
import threading
from dataclasses import dataclass

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients


################## VPC
class VPC:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.vpcs = []
        self.vpc_peering_connections = []
        self.vpc_endpoints = []
        self.vpc_endpoint_services = []
        self.__threading_call__(self.__describe_vpcs__)
        self.__threading_call__(self.__describe_vpc_peering_connections__)
        self.__threading_call__(self.__describe_vpc_endpoints__)
        self.__threading_call__(self.__describe_vpc_endpoint_services__)
        self.__describe_flow_logs__()
        self.__describe_route_tables__()
        self.__describe_vpc_endpoint_service_permissions__()

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
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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
                            if "DestinationCidrBlock" in route:
                                destination_cidrs.append(route["DestinationCidrBlock"])
                    conn.route_tables.append(
                        Route(
                            route_table["RouteTableId"],
                            destination_cidrs,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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

    def __describe_vpc_endpoints__(self, regional_client):
        logger.info("VPC - Describing VPC Endpoints...")
        try:
            describe_vpc_endpoints_paginator = regional_client.get_paginator(
                "describe_vpc_endpoints"
            )
            for page in describe_vpc_endpoints_paginator.paginate():
                for endpoint in page["VpcEndpoints"]:
                    endpoint_policy = None
                    if endpoint.get("PolicyDocument"):
                        endpoint_policy = json.loads(endpoint["PolicyDocument"])
                    self.vpc_endpoints.append(
                        VpcEndpoint(
                            endpoint["VpcEndpointId"],
                            endpoint["VpcId"],
                            endpoint["State"],
                            endpoint_policy,
                            endpoint["OwnerId"],
                            regional_client.region,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_vpc_endpoint_services__(self, regional_client):
        logger.info("VPC - Describing VPC Endpoint Services...")
        try:
            describe_vpc_endpoint_services_paginator = regional_client.get_paginator(
                "describe_vpc_endpoint_services"
            )
            for page in describe_vpc_endpoint_services_paginator.paginate():
                for endpoint in page["ServiceDetails"]:
                    if endpoint["Owner"] != "amazon":
                        self.vpc_endpoint_services.append(
                            VpcEndpointService(
                                endpoint["ServiceId"],
                                endpoint["ServiceName"],
                                endpoint["Owner"],
                                regional_client.region,
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_vpc_endpoint_service_permissions__(self):
        logger.info("VPC - Describing VPC Endpoint service permissions...")
        try:
            for service in self.vpc_endpoint_services:
                regional_client = self.regional_clients[service.region]
                for (
                    principal
                ) in regional_client.describe_vpc_endpoint_service_permissions(
                    ServiceId=service.id
                )[
                    "AllowedPrincipals"
                ]:
                    service.allowed_principals.append(principal["Principal"])
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


@dataclass
class VpcEndpoint:
    id: str
    vpc_id: str
    state: str
    policy_document: dict
    owner_id: list[Route]
    region: str

    def __init__(
        self,
        id,
        vpc_id,
        state,
        policy_document,
        owner_id,
        region,
    ):
        self.id = id
        self.vpc_id = vpc_id
        self.state = state
        self.policy_document = policy_document
        self.owner_id = owner_id
        self.route_tables = []
        self.region = region


@dataclass
class VpcEndpointService:
    id: str
    service: str
    owner_id: str
    allowed_principals: list
    region: str

    def __init__(
        self,
        id,
        service,
        owner_id,
        region,
    ):
        self.id = id
        self.service = service
        self.owner_id = owner_id
        self.allowed_principals = []
        self.region = region
