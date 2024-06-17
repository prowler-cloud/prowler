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

from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
from prowler.providers.aws.services.ecs.ecs_service import ECS
from prowler.providers.aws.services.ec2.ec2_service import EC2


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
    def test_no_elbs_or_clusters(self):
        ecs_client = mock.MagicMock
        ecs_client.clusters = {}

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 0
    
    @mock_aws
    def test_public_elbs_and_no_clusters(self):
        ecs_client = mock.MagicMock
        ecs_client.clusters = {}

        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group for load balancer"
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
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 0
    
    @mock_aws
    def test_internal_elbs_and_no_clusters(self):
        ecs_client = mock.MagicMock
        ecs_client.clusters = {}

        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group for load balancer"
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
            Scheme="internal",
            SecurityGroups=[security_group.id],
            Type="application",
        )["LoadBalancers"][0]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ecs_client,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 0
    
    @mock_aws
    def test_public_container_instances_behind_public_lb_ipv4(self):
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        ecs_client = client("ecs", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="First One"
        )

        security_group2 = ec2.create_security_group(
            GroupName="sg02", Description="Second one"
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        ec2_client.authorize_security_group_ingress(
            GroupId=security_group2.id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # ALB Client
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)

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
            IpAddressType="ipv4",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        task_definition = ecs_client.register_task_definition(
            family="sleep360",
            containerDefinitions=[
                {
                    "name": "sleep",
                    'command': [
                        'sleep',
                        '360',
                    ],
                    'cpu': 10,
                    'essential': True,
                    'image': 'busybox',
                    'memory': 10,
                },
            ],
            taskRoleArn='',
            volumes=[]
        )

        task_definition_arn = task_definition["taskDefinition"]["taskDefinitionArn"]

        # ecs container instance
        cluster_response = ecs_client.create_cluster(
            clusterName="test-cluster",
        )

        cluster_arn = cluster_response["cluster"]["clusterArn"]

        service_response = ecs_client.create_service(
            cluster=cluster_arn,
            serviceName="test-service",
            taskDefinition=task_definition_arn,
            loadBalancers=[
                {"targetGroupArn": target_group_arn, "loadBalancerName": lb["LoadBalancerName"]},
            ],
            desiredCount=1,
            launchType="EC2",
            placementConstraints=[],
        )

        container_instances = ecs_client.list_container_instances(
            cluster=cluster_arn
        )["containerInstanceArns"]

        print(container_instances)

        container_instances = ecs_client.describe_container_instances(
            cluster=cluster_arn,
            containerInstances=container_instances
        )["containerInstances"]

        container_instance_ips = [
            instance["ec2InstanceId"]
            for instance in container_instances
        ]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": ip}
                for ip in container_instance_ips
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_client",
            new=ECS(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ecs.ecs_container_not_directly_publicly_accessible_via_elbv2.ecs_container_not_directly_publicly_accessible_via_elbv2 import (
                ecs_container_not_directly_publicly_accessible_via_elbv2,
            )

            check = ecs_container_not_directly_publicly_accessible_via_elbv2()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECS Container '{container_instances}' is publicly accesible through an Internet facing Load Balancer '{lb["DNSName"]}'."
            )
            assert result[0].resource_arn == container_instances
            assert result[0].resource_tags == []
