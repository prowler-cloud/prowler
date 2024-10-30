from base64 import b64decode

import botocore
import mock
from boto3 import client
from moto import mock_aws

from prowler.config.config import encoding_format_utf_8
from prowler.providers.aws.services.autoscaling.autoscaling_service import (
    ApplicationAutoScaling,
    AutoScaling,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "my-autoscaling-group",
                    "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:autoScalingGroupName/my-autoscaling-group",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "CapacityRebalance": True,
                    "Tags": [
                        {
                            "Key": "tag_test",
                            "PropagateAtLaunch": False,
                            "ResourceId": "my-autoscaling-group",
                            "ResourceType": "auto-scaling-group",
                            "Value": "value_test",
                        }
                    ],
                    "Instances": [
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f4",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f5",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f6",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1b",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f7",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1b",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_AutoScaling_Service:
    # Test AutoScaling Service
    @mock_aws
    def test_service(self):
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert autoscaling.service == "autoscaling"

    # Test AutoScaling Client
    @mock_aws
    def test_client(self):
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        for regional_client in autoscaling.regional_clients.values():
            assert regional_client.__class__.__name__ == "AutoScaling"

    # Test AutoScaling Session
    @mock_aws
    def test__get_session__(self):
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert autoscaling.session.__class__.__name__ == "Session"

    # Test AutoScaling Session
    @mock_aws
    def test_audited_account(self):
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert autoscaling.audited_account == AWS_ACCOUNT_NUMBER

    # Test AutoScaling Get APIs
    @mock_aws
    def test_describe_launch_configurations(self):
        # Generate AutoScaling Client
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        # Create AutoScaling API
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester1",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="DB_PASSWORD=foobar123",
            AssociatePublicIpAddress=True,
        )
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester2",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            MetadataOptions={
                "HttpTokens": "required",
                "HttpPutResponseHopLimit": 123,
                "HttpEndpoint": "enabled",
            },
        )
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert len(autoscaling.launch_configurations) == 2
        launch_configurations = autoscaling.launch_configurations
        arn_tester1 = next(
            arn
            for arn, config in launch_configurations.items()
            if config.name == "tester1"
        )
        arn_tester2 = next(
            arn
            for arn, config in launch_configurations.items()
            if config.name == "tester2"
        )
        assert arn_tester1 in launch_configurations
        assert (
            b64decode(launch_configurations[arn_tester1].user_data).decode(
                encoding_format_utf_8
            )
            == "DB_PASSWORD=foobar123"
        )
        assert launch_configurations[arn_tester1].image_id == "ami-12c6146b"
        assert launch_configurations[arn_tester1].public_ip
        assert arn_tester2 in launch_configurations
        assert launch_configurations[arn_tester2].image_id == "ami-12c6146b"
        assert launch_configurations[arn_tester2].http_tokens == "required"
        assert launch_configurations[arn_tester2].http_endpoint == "enabled"

    # Test Describe Auto Scaling Groups With Botocore
    @mock_aws
    def test_describe_auto_scaling_groups_with_attached_instances(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call
        ):
            # Generate AutoScaling Client
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName="my-autoscaling-group",
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a", "us-east-1b"],
                CapacityRebalance=True,
                Tags=[
                    {
                        "Key": "tag_test",
                        "Value": "value_test",
                    },
                ],
            )

            # AutoScaling client for this test class
            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            autoscaling = AutoScaling(aws_provider)
            assert len(autoscaling.groups) == 1
            # create_auto_scaling_group doesn't return the ARN, can't check it
            # assert autoscaling.groups[0].arn ==
            assert autoscaling.groups[0].name == "my-autoscaling-group"
            assert autoscaling.groups[0].region == AWS_REGION_US_EAST_1
            assert autoscaling.groups[0].availability_zones == [
                "us-east-1a",
                "us-east-1b",
            ]
            assert autoscaling.groups[0].capacity_rebalance
            assert autoscaling.groups[0].tags == [
                {
                    "Key": "tag_test",
                    "PropagateAtLaunch": False,
                    "ResourceId": "my-autoscaling-group",
                    "ResourceType": "auto-scaling-group",
                    "Value": "value_test",
                }
            ]
            assert autoscaling.groups[0].instance_types == [
                "t2.micro",
                "t3.large",
                "t2.micro",
                "t3.large",
            ]
            assert autoscaling.groups[0].az_instance_types == {
                "us-east-1a": {"t2.micro", "t3.large"},
                "us-east-1b": {"t2.micro", "t3.large"},
            }

    # Test Describe Auto Scaling Groups
    @mock_aws
    def test_describe_auto_scaling_groups(self):
        # Generate AutoScaling Client
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName="test",
            LaunchTemplateData={
                "ImageId": "ami-12c6146b",
                "InstanceType": "t1.micro",
                "KeyName": "the_keys",
                "SecurityGroups": ["default", "default2"],
            },
        )

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        elastic_load_balancer = client("elbv2", region_name=AWS_REGION_US_EAST_1)
        target_group = elastic_load_balancer.create_target_group(
            Name="my-target-group",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            HealthCheckProtocol="HTTP",
            HealthCheckPort="80",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            Matcher={"HttpCode": "200"},
        )

        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group",
            LaunchTemplate={"LaunchTemplateName": "test", "Version": "$Latest"},
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
            Tags=[
                {
                    "Key": "tag_test",
                    "Value": "value_test",
                },
            ],
        )

        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group-2",
            MixedInstancesPolicy={
                "LaunchTemplate": {
                    "LaunchTemplateSpecification": {
                        "LaunchTemplateName": "test",
                        "Version": "$Latest",
                    },
                    "Overrides": [
                        {
                            "InstanceType": "t2.micro",
                            "WeightedCapacity": "1",
                        },
                    ],
                },
            },
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
            Tags=[
                {
                    "Key": "tag_test",
                    "Value": "value_test",
                },
            ],
            HealthCheckType="ELB",
            LoadBalancerNames=["my-load-balancer"],
            TargetGroupARNs=[target_group["TargetGroups"][0]["TargetGroupArn"]],
        )

        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="DB_PASSWORD=foobar123",
            AssociatePublicIpAddress=True,
        )

        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group-3",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
            Tags=[],
        )

        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert len(autoscaling.groups) == 3
        for group in autoscaling.groups:
            if group.name == "my-autoscaling-group":
                assert (
                    group.arn
                    == autoscaling_client.describe_auto_scaling_groups(
                        AutoScalingGroupNames=["my-autoscaling-group"]
                    )["AutoScalingGroups"][0]["AutoScalingGroupARN"]
                )
                assert group.name == "my-autoscaling-group"
                assert group.region == AWS_REGION_US_EAST_1
                assert group.availability_zones == ["us-east-1a", "us-east-1b"]
                assert group.tags == [
                    {
                        "Key": "tag_test",
                        "PropagateAtLaunch": False,
                        "ResourceId": "my-autoscaling-group",
                        "ResourceType": "auto-scaling-group",
                        "Value": "value_test",
                    }
                ]
                assert group.launch_template["LaunchTemplateName"] == "test"
                assert not group.mixed_instances_policy_launch_template
                assert group.health_check_type == "EC2"
                assert not group.load_balancers
                assert not group.target_groups
                assert not group.launch_configuration_name
            elif group.name == "my-autoscaling-group-2":
                assert (
                    group.arn
                    == autoscaling_client.describe_auto_scaling_groups(
                        AutoScalingGroupNames=["my-autoscaling-group-2"]
                    )["AutoScalingGroups"][0]["AutoScalingGroupARN"]
                )
                assert group.name == "my-autoscaling-group-2"
                assert group.region == AWS_REGION_US_EAST_1
                assert group.availability_zones == ["us-east-1a", "us-east-1b"]
                assert group.tags == [
                    {
                        "Key": "tag_test",
                        "PropagateAtLaunch": False,
                        "ResourceId": "my-autoscaling-group-2",
                        "ResourceType": "auto-scaling-group",
                        "Value": "value_test",
                    }
                ]
                assert not group.launch_template
                assert (
                    group.mixed_instances_policy_launch_template["LaunchTemplateName"]
                    == "test"
                )
                assert group.health_check_type == "ELB"
                assert group.load_balancers == ["my-load-balancer"]
                assert group.target_groups == [
                    target_group["TargetGroups"][0]["TargetGroupArn"]
                ]
                assert not group.launch_configuration_name
            elif group.name == "my-autoscaling-group-3":
                assert (
                    group.arn
                    == autoscaling_client.describe_auto_scaling_groups(
                        AutoScalingGroupNames=["my-autoscaling-group-3"]
                    )["AutoScalingGroups"][0]["AutoScalingGroupARN"]
                )
                assert group.name == "my-autoscaling-group-3"
                assert group.region == AWS_REGION_US_EAST_1
                assert group.availability_zones == ["us-east-1a", "us-east-1b"]
                assert not group.tags
                assert not group.launch_template
                assert not group.mixed_instances_policy_launch_template
                assert group.health_check_type == "EC2"
                assert not group.load_balancers
                assert not group.target_groups
                assert group.launch_configuration_name == "test"

    # Test Application AutoScaling Describe Scalable Targets
    @mock_aws
    def test_application_auto_scaling_scalable_targets(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table = dynamodb_client.create_table(
            TableName="test1",
            AttributeDefinitions=[
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "app", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "client", "KeyType": "HASH"},
                {"AttributeName": "app", "KeyType": "RANGE"},
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )["TableDescription"]

        autoscaling_client = client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        )
        autoscaling_client.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=f"table/{table['TableName']}",
            ScalableDimension="dynamodb:table:ReadCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = ApplicationAutoScaling(aws_provider)
        assert len(autoscaling.scalable_targets) == 1
        assert autoscaling.scalable_targets[0].service_namespace == "dynamodb"
        assert autoscaling.scalable_targets[0].resource_id == "table/test1"
        assert (
            autoscaling.scalable_targets[0].scalable_dimension
            == "dynamodb:table:ReadCapacityUnits"
        )
