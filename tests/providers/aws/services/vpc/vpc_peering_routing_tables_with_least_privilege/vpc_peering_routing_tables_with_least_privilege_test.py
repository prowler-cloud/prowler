from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_vpc_peering_routing_tables_with_least_privilege:
    @mock_aws
    def test_vpc_no_peering_connections(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege.vpc_client",
                new=VPC(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege import (
                    vpc_peering_routing_tables_with_least_privilege,
                )

                check = vpc_peering_routing_tables_with_least_privilege()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_comply_peering_connection_(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPCs peers as well as a comply route
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        peer_vpc = ec2_client.create_vpc(CidrBlock="11.0.0.0/16")
        vpc_pcx = ec2_client.create_vpc_peering_connection(
            VpcId=vpc["Vpc"]["VpcId"], PeerVpcId=peer_vpc["Vpc"]["VpcId"]
        )
        vpc_pcx_id = vpc_pcx["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        vpc_pcx = ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_pcx_id
        )
        main_route_table_id = ec2_client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc["Vpc"]["VpcId"]]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        main_route_table = ec2_resource.RouteTable(main_route_table_id)
        main_route_table.create_route(
            DestinationCidrBlock="10.0.0.4/24", VpcPeeringConnectionId=vpc_pcx_id
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC, Route

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege.vpc_client",
                new=VPC(current_audit_info),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege import (
                    vpc_peering_routing_tables_with_least_privilege,
                )

                service_client.vpc_peering_connections[0].route_tables = [
                    Route(
                        id=main_route_table_id,
                        destination_cidrs=["10.12.23.44/32"],
                    )
                ]
                check = vpc_peering_routing_tables_with_least_privilege()
                result = check.execute()

                assert len(result) == len(
                    ec2_client.describe_vpc_peering_connections()[
                        "VpcPeeringConnections"
                    ]
                )
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Peering Connection {vpc_pcx_id} comply with least privilege access."
                )
                assert result[0].resource_id == vpc_pcx_id
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_comply_peering_connection_edge_case(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPCs peers as well as a comply route
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        peer_vpc = ec2_client.create_vpc(CidrBlock="11.0.0.0/16")
        vpc_pcx = ec2_client.create_vpc_peering_connection(
            VpcId=vpc["Vpc"]["VpcId"], PeerVpcId=peer_vpc["Vpc"]["VpcId"]
        )
        vpc_pcx_id = vpc_pcx["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        vpc_pcx = ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_pcx_id
        )
        main_route_table_id = ec2_client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc["Vpc"]["VpcId"]]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        main_route_table = ec2_resource.RouteTable(main_route_table_id)
        main_route_table.create_route(DestinationCidrBlock="0.0.0.0/0")

        from prowler.providers.aws.services.vpc.vpc_service import VPC, Route

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege.vpc_client",
                new=VPC(current_audit_info),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege import (
                    vpc_peering_routing_tables_with_least_privilege,
                )

                service_client.vpc_peering_connections[0].route_tables = [
                    Route(
                        id=main_route_table_id,
                        destination_cidrs=["10.12.23.44/32"],
                    )
                ]
                check = vpc_peering_routing_tables_with_least_privilege()
                result = check.execute()

                assert len(result) == len(
                    ec2_client.describe_vpc_peering_connections()[
                        "VpcPeeringConnections"
                    ]
                )
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Peering Connection {vpc_pcx_id} comply with least privilege access."
                )
                assert result[0].resource_id == vpc_pcx_id
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_not_comply_peering_connection_(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPCs peers as well as a comply route
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        peer_vpc = ec2_client.create_vpc(CidrBlock="11.0.0.0/16")
        vpc_pcx = ec2_client.create_vpc_peering_connection(
            VpcId=vpc["Vpc"]["VpcId"], PeerVpcId=peer_vpc["Vpc"]["VpcId"]
        )
        vpc_pcx_id = vpc_pcx["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        vpc_pcx = ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_pcx_id
        )
        main_route_table_id = ec2_client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc["Vpc"]["VpcId"]]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        main_route_table = ec2_resource.RouteTable(main_route_table_id)
        main_route_table.create_route(
            DestinationCidrBlock="10.0.0.0/16", VpcPeeringConnectionId=vpc_pcx_id
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC, Route

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege.vpc_client",
                new=VPC(current_audit_info),
            ) as service_client:
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_peering_routing_tables_with_least_privilege.vpc_peering_routing_tables_with_least_privilege import (
                    vpc_peering_routing_tables_with_least_privilege,
                )

                service_client.vpc_peering_connections[0].route_tables = [
                    Route(
                        id=main_route_table_id,
                        destination_cidrs=["10.0.0.0/16"],
                    )
                ]
                check = vpc_peering_routing_tables_with_least_privilege()
                result = check.execute()

                assert len(result) == len(
                    ec2_client.describe_vpc_peering_connections()[
                        "VpcPeeringConnections"
                    ]
                )
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"VPC Peering Connection {vpc_pcx_id} does not comply with least privilege access since it accepts whole VPCs CIDR in its route tables."
                )
                assert result[0].resource_id == vpc_pcx_id
                assert result[0].region == AWS_REGION_US_EAST_1
