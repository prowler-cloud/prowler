import json
import threading
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.aws_provider import generate_regional_clients


################## VPC
class VPC:
    def __init__(self, audit_info):
        self.service = "ec2"
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audit_resources = audit_info.audit_resources
        self.audited_partition = audit_info.audited_partition
        self.audited_account_arn = audit_info.audited_account_arn
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.vpcs = {}
        self.vpc_peering_connections = []
        self.vpc_endpoints = []
        self.vpc_endpoint_services = []
        self.__threading_call__(self.__describe_vpcs__)
        self.__threading_call__(self.__describe_vpc_peering_connections__)
        self.__threading_call__(self.__describe_vpc_endpoints__)
        self.__threading_call__(self.__describe_vpc_endpoint_services__)
        self.__describe_flow_logs__()
        self.__describe_peering_route_tables__()
        self.__describe_vpc_endpoint_service_permissions__()
        self.vpc_subnets = {}
        self.__threading_call__(self.__describe_vpc_subnets__)
        self.region = (
            audit_info.profile_region
            if audit_info.profile_region
            else list(self.regional_clients.keys())[0]
        )

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
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:vpc/{vpc['VpcId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.vpcs[vpc["VpcId"]] = VPCs(
                            arn=arn,
                            id=vpc["VpcId"],
                            default=vpc["IsDefault"],
                            cidr_block=vpc["CidrBlock"],
                            region=regional_client.region,
                            tags=vpc.get("Tags"),
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
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:vpc-peering-connection/{conn['VpcPeeringConnectionId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        conn["AccepterVpcInfo"]["CidrBlock"] = None
                        self.vpc_peering_connections.append(
                            VpcPeeringConnection(
                                arn=arn,
                                id=conn["VpcPeeringConnectionId"],
                                accepter_vpc=conn["AccepterVpcInfo"]["VpcId"],
                                accepter_cidr=conn["AccepterVpcInfo"].get("CidrBlock"),
                                requester_vpc=conn["RequesterVpcInfo"]["VpcId"],
                                requester_cidr=conn["RequesterVpcInfo"].get(
                                    "CidrBlock"
                                ),
                                region=regional_client.region,
                                tags=conn.get("Tags"),
                            )
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_peering_route_tables__(self):
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
                            id=route_table["RouteTableId"],
                            destination_cidrs=destination_cidrs,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __describe_flow_logs__(self):
        logger.info("VPC - Describing flow logs...")
        try:
            for vpc in self.vpcs.values():
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
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __describe_vpc_endpoints__(self, regional_client):
        logger.info("VPC - Describing VPC Endpoints...")
        try:
            describe_vpc_endpoints_paginator = regional_client.get_paginator(
                "describe_vpc_endpoints"
            )
            for page in describe_vpc_endpoints_paginator.paginate():
                for endpoint in page["VpcEndpoints"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:vpc-endpoint/{endpoint['VpcEndpointId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        endpoint_policy = None
                        if endpoint.get("PolicyDocument"):
                            endpoint_policy = json.loads(endpoint["PolicyDocument"])
                        self.vpc_endpoints.append(
                            VpcEndpoint(
                                arn=arn,
                                id=endpoint["VpcEndpointId"],
                                vpc_id=endpoint["VpcId"],
                                state=endpoint["State"],
                                policy_document=endpoint_policy,
                                owner_id=endpoint["OwnerId"],
                                region=regional_client.region,
                                tags=endpoint.get("Tags"),
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
                        arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:vpc-endpoint-service/{endpoint['ServiceId']}"
                        if not self.audit_resources or (
                            is_resource_filtered(arn, self.audit_resources)
                        ):
                            self.vpc_endpoint_services.append(
                                VpcEndpointService(
                                    arn=arn,
                                    id=endpoint["ServiceId"],
                                    service=endpoint["ServiceName"],
                                    owner_id=endpoint["Owner"],
                                    region=regional_client.region,
                                    tags=endpoint.get("Tags"),
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
                try:
                    for (
                        principal
                    ) in regional_client.describe_vpc_endpoint_service_permissions(
                        ServiceId=service.id
                    )[
                        "AllowedPrincipals"
                    ]:
                        service.allowed_principals.append(principal["Principal"])
                except ClientError as error:
                    if (
                        error.response["Error"]["Code"]
                        == "InvalidVpcEndpointServiceId.NotFound"
                    ):
                        logger.warning(
                            f"{service.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def __describe_vpc_subnets__(self, regional_client):
        logger.info("VPC - Describing VPC subnets...")
        try:
            describe_subnets_paginator = regional_client.get_paginator(
                "describe_subnets"
            )
            for page in describe_subnets_paginator.paginate():
                for subnet in page["Subnets"]:
                    if not self.audit_resources or (
                        is_resource_filtered(subnet["SubnetArn"], self.audit_resources)
                    ):
                        try:
                            # Check the route table associated with the subnet to see if it's public
                            regional_client_for_subnet = self.regional_clients[
                                regional_client.region
                            ]
                            route_tables_for_subnet = (
                                regional_client_for_subnet.describe_route_tables(
                                    Filters=[
                                        {
                                            "Name": "association.subnet-id",
                                            "Values": [subnet["SubnetId"]],
                                        }
                                    ]
                                )
                            )
                            if not route_tables_for_subnet.get("RouteTables"):
                                # If a subnet is not explicitly associated with any route table, it is implicitly associated with the main route table.
                                route_tables_for_subnet = (
                                    regional_client_for_subnet.describe_route_tables(
                                        Filters=[
                                            {
                                                "Name": "association.main",
                                                "Values": ["true"],
                                            }
                                        ]
                                    )
                                )
                            public = False
                            nat_gateway = False
                            for route in route_tables_for_subnet.get("RouteTables")[
                                0
                            ].get("Routes"):
                                if "GatewayId" in route and "igw" in route["GatewayId"]:
                                    public = True
                                if "NatGatewayId" in route:
                                    nat_gateway = True
                            # Add it to to list of vpc_subnets and to the VPC object
                            object = VpcSubnet(
                                arn=subnet["SubnetArn"],
                                id=subnet["SubnetId"],
                                default=subnet["DefaultForAz"],
                                vpc_id=subnet["VpcId"],
                                cidr_block=subnet["CidrBlock"],
                                region=regional_client.region,
                                availability_zone=subnet["AvailabilityZone"],
                                public=public,
                                nat_gateway=nat_gateway,
                                tags=subnet.get("Tags"),
                                mapPublicIpOnLaunch=subnet["MapPublicIpOnLaunch"],
                            )
                            self.vpc_subnets[subnet["SubnetId"]] = object
                            # Add it to the VPC object
                            for vpc in self.vpcs.values():
                                if vpc.id == subnet["VpcId"]:
                                    vpc.subnets.append(object)
                        except Exception as error:
                            logger.error(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class VpcSubnet(BaseModel):
    arn: str
    id: str
    default: bool
    vpc_id: str
    cidr_block: str
    availability_zone: str
    public: bool
    nat_gateway: bool
    region: str
    mapPublicIpOnLaunch: bool
    tags: Optional[list] = []


class VPCs(BaseModel):
    arn: str
    id: str
    default: bool
    cidr_block: str
    flow_log: bool = False
    region: str
    subnets: list[VpcSubnet] = []
    tags: Optional[list] = []


class Route(BaseModel):
    id: str
    destination_cidrs: list[str]


class VpcPeeringConnection(BaseModel):
    arn: str
    id: str
    accepter_vpc: str
    accepter_cidr: Optional[str]
    requester_vpc: str
    requester_cidr: Optional[str]
    route_tables: list[Route] = []
    region: str
    tags: Optional[list] = []


class VpcEndpoint(BaseModel):
    arn: str
    id: str
    vpc_id: str
    state: str
    policy_document: Optional[dict]
    owner_id: str
    region: str
    tags: Optional[list] = []


class VpcEndpointService(BaseModel):
    arn: str
    id: str
    service: str
    owner_id: str
    allowed_principals: list = []
    region: str
    tags: Optional[list] = []
