from unittest import mock

from boto3 import client, resource, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_vpc_peering_routing_tables_with_least_privilege:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_ec2
    def test_vpc_no_peering_connections(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = self.set_mocked_audit_info()

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

    @mock_ec2
    def test_vpc_comply_peering_connection_(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)

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

        current_audit_info = self.set_mocked_audit_info()

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
                assert result[0].region == AWS_REGION

    @mock_ec2
    def test_vpc_not_comply_peering_connection_(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_resource = resource("ec2", region_name=AWS_REGION)

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

        current_audit_info = self.set_mocked_audit_info()

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
                assert result[0].region == AWS_REGION
