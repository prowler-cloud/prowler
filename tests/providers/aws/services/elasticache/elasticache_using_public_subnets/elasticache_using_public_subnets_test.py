from unittest import mock

from boto3 import client, session
from moto import mock_ec2, mock_elasticache

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.elasticache.elasticache_service import (
    ElastiCacheInstance,
)
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_elasticache_using_public_subnets:
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

    # def test_no_clusters(self):
    #     from prowler.providers.aws.services.elasticache.elasticache_service import (
    #         Elasticache,
    #     )

    #     current_audit_info = self.set_mocked_audit_info()

    #     with mock.patch(
    #         "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
    #         new=current_audit_info,
    #     ), mock.patch(
    #         "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client",
    #         new=Elasticache(current_audit_info),
    #     ):
    #         # Test Check
    #         from prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets import (
    #             elasticache_using_public_subnets,
    #         )

    #         check = elasticache_using_public_subnets()
    #         result = check.execute()

    #         assert len(result) == 0

    @mock_ec2
    @mock_elasticache
    def test_cluster_with_both_public_and_private_subnets(self):
        # Create Elasticache Mocked Resources
        elasticache_client = client("elasticache", region_name=AWS_REGION)
        cluster = elasticache_client.create_cache_cluster(
            CacheClusterId="test", Engine="memcached", CacheSubnetGroupName="default"
        )
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24"
        )
        route_table_private = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private["Subnet"]["SubnetId"],
        )
        subnet_public = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.2.0/24"
        )
        route_table_public = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        igw = ec2_client.create_internet_gateway()
        ec2_client.create_route(
            DestinationCidrBlock="0.0.0.0",
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            GatewayId=igw["InternetGateway"]["InternetGatewayId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            SubnetId=subnet_public["Subnet"]["SubnetId"],
        )

        ## Code prepared to when moto support "create_cache_subnet_group"
        # subnet_group = elasticache_client.create_cache_subnet_group(
        #     CacheSubnetGroupName="default",
        #     CacheSubnetGroupDescription="test",
        #     SubnetIds=[subnet_private["Subnet"]["SubnetId"], subnet_public["Subnet"]["SubnetId"]]
        # )

        from prowler.providers.aws.services.elasticache.elasticache_service import (
            Elasticache,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client",
            new=Elasticache(current_audit_info),
        ):
            # Mock needed due to lack of support for "create_cache_subnet_group" on moto.
            with mock.patch(
                "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client.elasticache_instances",
                new=[
                    ElastiCacheInstance(
                        cache_cluster_id=cluster["CacheCluster"]["CacheClusterId"],
                        arn=cluster["CacheCluster"]["ARN"],
                        cache_node_type=cluster["CacheCluster"]["CacheNodeType"],
                        engine=cluster["CacheCluster"]["Engine"],
                        engine_version=cluster["CacheCluster"]["EngineVersion"],
                        availability_zone=cluster["CacheCluster"][
                            "PreferredAvailabilityZone"
                        ],
                        subnet_group=[
                            {
                                "CacheSubnetGroupName": "default",
                                "CacheSubnetGroupDescription": " ",
                                "VpcId": vpc["Vpc"]["VpcId"],
                                "Subnets": [
                                    {
                                        "SubnetIdentifier": subnet_private["Subnet"][
                                            "SubnetId"
                                        ]
                                    },
                                    {
                                        "SubnetIdentifier": subnet_public["Subnet"][
                                            "SubnetId"
                                        ]
                                    },
                                ],
                            }
                        ],
                    )
                ],
            ):
                print(dir(elasticache_client))
                # Test Check
                from prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets import (
                    elasticache_using_public_subnets,
                )

                check = elasticache_using_public_subnets()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"

    # @mock_ec2
    # @mock_elasticache
    # def test_cluster_with_public_subnets(self):
    #     # Create Elasticache Mocked Resources
    #     elasticache_client = client("elasticache", region_name=AWS_REGION)
    #     cluster = elasticache_client.create_cache_cluster(
    #         CacheClusterId="test", Engine="memcached", CacheSubnetGroupName="default"
    #     )
    #     ec2_client = client("ec2", region_name=AWS_REGION)
    #     vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    #     subnet_public1 = ec2_client.create_subnet(
    #         VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24"
    #     )
    #     route_table_public1 = ec2_client.create_route_table(
    #         VpcId=vpc["Vpc"]["VpcId"],
    #     )
    #     igw1 = ec2_client.create_internet_gateway()
    #     ec2_client.create_route(
    #         DestinationCidrBlock="10.10.10.0",
    #         RouteTableId=route_table_public1["RouteTable"]["RouteTableId"],
    #         GatewayId=igw1["InternetGateway"]["InternetGatewayId"],
    #     )
    #     ec2_client.associate_route_table(
    #         RouteTableId=route_table_public1["RouteTable"]["RouteTableId"],
    #         SubnetId=subnet_public1["Subnet"]["SubnetId"],
    #     )
    #     subnet_public2 = ec2_client.create_subnet(
    #         VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.2.0/24"
    #     )
    #     route_table_public2 = ec2_client.create_route_table(
    #         VpcId=vpc["Vpc"]["VpcId"],
    #     )
    #     igw2 = ec2_client.create_internet_gateway()
    #     ec2_client.create_route(
    #         DestinationCidrBlock="0.0.0.0",
    #         RouteTableId=route_table_public2["RouteTable"]["RouteTableId"],
    #         GatewayId=igw2["InternetGateway"]["InternetGatewayId"],
    #     )
    #     ec2_client.associate_route_table(
    #         RouteTableId=route_table_public2["RouteTable"]["RouteTableId"],
    #         SubnetId=subnet_public2["Subnet"]["SubnetId"],
    #     )
    #     ## Code prepared to when moto support "create_cache_subnet_group"
    #     # subnet_group = elasticache_client.create_cache_subnet_group(
    #     #     CacheSubnetGroupName="default",
    #     #     CacheSubnetGroupDescription="test",
    #     #     SubnetIds=[subnet_public1["Subnet"]["SubnetId"], subnet_public2["Subnet"]["SubnetId"]]
    #     # )

    #     from prowler.providers.aws.services.elasticache.elasticache_service import (
    #         Elasticache,
    #     )

    #     current_audit_info = self.set_mocked_audit_info()

    #     with mock.patch(
    #         "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
    #         new=current_audit_info,
    #     ), mock.patch(
    #         "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client",
    #         new=Elasticache(current_audit_info),
    #     ):
    #         # Mock needed due to lack of support for "create_cache_subnet_group" on moto.
    #         with mock.patch(
    #             "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client.elasticache_instances",
    #             new=[
    #                 ElastiCacheInstance(
    #                     cache_cluster_id=cluster["CacheCluster"]["CacheClusterId"],
    #                     arn=cluster["CacheCluster"]["ARN"],
    #                     cache_node_type=cluster["CacheCluster"]["CacheNodeType"],
    #                     engine=cluster["CacheCluster"]["Engine"],
    #                     engine_version=cluster["CacheCluster"]["EngineVersion"],
    #                     availability_zone=cluster["CacheCluster"][
    #                         "PreferredAvailabilityZone"
    #                     ],
    #                     subnet_group=[
    #                         {
    #                             "CacheSubnetGroupName": "default",
    #                             "CacheSubnetGroupDescription": " ",
    #                             "VpcId": vpc["Vpc"]["VpcId"],
    #                             "Subnets": [
    #                                 {
    #                                     "SubnetIdentifier": subnet_public1["Subnet"][
    #                                         "SubnetId"
    #                                     ]
    #                                 },
    #                                 {
    #                                     "SubnetIdentifier": subnet_public2["Subnet"][
    #                                         "SubnetId"
    #                                     ]
    #                                 },
    #                             ],
    #                         }
    #                     ],
    #                 )
    #             ],
    #         ):
    #             # Test Check
    #             from prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets import (
    #                 elasticache_using_public_subnets,
    #             )

    #             check = elasticache_using_public_subnets()
    #             result = check.execute()

    #             assert len(result) == 1
    #             assert result[0].status == "FAIL"

    # @mock_ec2
    # @mock_elasticache
    # def test_cluster_with_private_subnets(self):
    #     # Create Elasticache Mocked Resources
    #     elasticache_client = client("elasticache", region_name=AWS_REGION)
    #     cluster = elasticache_client.create_cache_cluster(
    #         CacheClusterId="test", Engine="memcached", CacheSubnetGroupName="default"
    #     )
    #     ec2_client = client("ec2", region_name=AWS_REGION)
    #     vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    #     subnet_private1 = ec2_client.create_subnet(
    #         VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.1.0/24"
    #     )
    #     route_table_private1 = ec2_client.create_route_table(
    #         VpcId=vpc["Vpc"]["VpcId"],
    #     )
    #     ec2_client.create_route(
    #         DestinationCidrBlock="10.10.10.0",
    #         RouteTableId=route_table_private1["RouteTable"]["RouteTableId"],
    #     )
    #     ec2_client.associate_route_table(
    #         RouteTableId=route_table_private1["RouteTable"]["RouteTableId"],
    #         SubnetId=subnet_private1["Subnet"]["SubnetId"],
    #     )
    #     subnet_private2 = ec2_client.create_subnet(
    #         VpcId=vpc["Vpc"]["VpcId"], CidrBlock="10.0.2.0/24"
    #     )
    #     route_table_private2 = ec2_client.create_route_table(
    #         VpcId=vpc["Vpc"]["VpcId"],
    #     )
    #     ec2_client.create_route(
    #         DestinationCidrBlock="0.0.0.0",
    #         RouteTableId=route_table_private2["RouteTable"]["RouteTableId"],
    #     )
    #     ec2_client.associate_route_table(
    #         RouteTableId=route_table_private2["RouteTable"]["RouteTableId"],
    #         SubnetId=subnet_private2["Subnet"]["SubnetId"],
    #     )
    #     ## Code prepared to when moto support "create_cache_subnet_group"
    #     # subnet_group = elasticache_client.create_cache_subnet_group(
    #     #     CacheSubnetGroupName="default",
    #     #     CacheSubnetGroupDescription="test",
    #     #     SubnetIds=[subnet_private1["Subnet"]["SubnetId"], subnet_private2["Subnet"]["SubnetId"]]
    #     # )

    #     from prowler.providers.aws.services.elasticache.elasticache_service import (
    #         Elasticache,
    #     )

    #     current_audit_info = self.set_mocked_audit_info()

    #     with mock.patch(
    #         "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
    #         new=current_audit_info,
    #     ), mock.patch(
    #         "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client",
    #         new=Elasticache(current_audit_info),
    #     ):
    #         # Mock needed due to lack of support for "create_cache_subnet_group" on moto.
    #         with mock.patch(
    #             "prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets.elasticache_client.elasticache_instances",
    #             new=[
    #                 ElastiCacheInstance(
    #                     cache_cluster_id=cluster["CacheCluster"]["CacheClusterId"],
    #                     arn=cluster["CacheCluster"]["ARN"],
    #                     cache_node_type=cluster["CacheCluster"]["CacheNodeType"],
    #                     engine=cluster["CacheCluster"]["Engine"],
    #                     engine_version=cluster["CacheCluster"]["EngineVersion"],
    #                     availability_zone=cluster["CacheCluster"][
    #                         "PreferredAvailabilityZone"
    #                     ],
    #                     subnet_group=[
    #                         {
    #                             "CacheSubnetGroupName": "default",
    #                             "CacheSubnetGroupDescription": " ",
    #                             "VpcId": vpc["Vpc"]["VpcId"],
    #                             "Subnets": [
    #                                 {
    #                                     "SubnetIdentifier": subnet_private1["Subnet"][
    #                                         "SubnetId"
    #                                     ]
    #                                 },
    #                                 {
    #                                     "SubnetIdentifier": subnet_private2["Subnet"][
    #                                         "SubnetId"
    #                                     ]
    #                                 },
    #                             ],
    #                         }
    #                     ],
    #                 )
    #             ],
    #         ):
    #             # Test Check
    #             from prowler.providers.aws.services.elasticache.elasticache_using_public_subnets.elasticache_using_public_subnets import (
    #                 elasticache_using_public_subnets,
    #             )

    #             check = elasticache_using_public_subnets()
    #             result = check.execute()

    #             assert len(result) == 1
    #             assert result[0].status == "PASS"
