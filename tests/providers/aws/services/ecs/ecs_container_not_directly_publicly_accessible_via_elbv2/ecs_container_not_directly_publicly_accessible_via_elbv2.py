from re import search
from unittest import mock
from moto import mock_aws
from unittest.mock import patch

from boto3 import client, resource

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    AWS_ACCOUNT_NUMBER,
    set_mocked_aws_provider,
)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ecs_container_not_directly_publicly_accessible_via_elbv2:
    @mock_aws
    def test_no_elbs_or_container_instances(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.ecs.ecs_service import (
            Containers,
        )

        ecs_client = mock.MagicMock
        ecs_client.containers = []

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(set_mocked_aws_provider()),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 0


    @mock_aws
    def test_container_instances_behind_public_lb_ipv4(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.ecs.ecs_service import Containers

        #ecs container instance
        ecs_client = mock.MagicMock
        ecs_client.containers = [] #create container instances
        container_instance = "f2756532-8f13-4d53-87c9-aed50dc94cd7"
        ipv4Address = "192.168.0.1"
        ecs_client.containers.append(
            Containers(
                arn=f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:container-instance/{container_instance}",
                availability_zone=AWS_REGION_EU_WEST_1_AZA,
                ipv4=ipv4Address
            )
        )


        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc.id,
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="ip",
            IpAddressType='ipv4'
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": ipv4Address},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(set_mocked_aws_provider()),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is behind a internet facing load balancer",
                result[0].status_extended,
            )
    
    @mock_aws
    def test_container_instances_behind_public_lb_ipv6(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.ecs.ecs_service import Containers

        #ecs container instance
        ecs_client = mock.MagicMock
        ecs_client.containers = [] #create container instances
        container_instance = "f2756532-8f13-4d53-87c9-aed50dc94cd7"
        ipv6Address = "fd6b:21b0:4789::/48"
        ecs_client.containers.append(
            Containers(
                arn=f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:container-instance/{container_instance}",
                availability_zone=AWS_REGION_EU_WEST_1_AZA,
                ipv6=ipv6Address
            )
        )


        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc.id,
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="ip",
            IpAddressType='ipv6'
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": ipv6Address},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(set_mocked_aws_provider()),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "is behind a internet facing load balancer",
                result[0].status_extended,
            )

    @mock_aws
    def test_container_instances_behind_private_lb(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
        from prowler.providers.aws.services.ecs.ecs_service import Containers

        #ecs container instance
        ecs_client = mock.MagicMock
        ecs_client.containers = [] #create container instances
        container_instance = "f2756532-8f13-4d53-87c9-aed50dc94cd7"
        ipv6Address = "fd6b:21b0:4789::/48"
        ecs_client.containers.append(
            Containers(
                arn=f"arn:aws:ecs:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:container-instance/{container_instance}",
                availability_zone=AWS_REGION_EU_WEST_1_AZA,
                ipv6=ipv6Address
            )
        )


        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )

        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
            Type="application",
        )["LoadBalancers"][0]

        target_group = conn.create_target_group(
            Name="a-target",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc.id,
            HealthCheckEnabled=True,
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=35,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="ip",
            IpAddressType='ipv6'
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": ipv6Address},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(set_mocked_aws_provider()),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "is not behind any internet facing load balancer",
                result[0].status_extended,
            )