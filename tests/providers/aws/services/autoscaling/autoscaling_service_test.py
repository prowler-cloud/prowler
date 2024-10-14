from base64 import b64decode

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
        )
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester2",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert len(autoscaling.launch_configurations) == 2
        assert autoscaling.launch_configurations[0].name == "tester1"
        assert (
            b64decode(autoscaling.launch_configurations[0].user_data).decode(
                encoding_format_utf_8
            )
            == "DB_PASSWORD=foobar123"
        )
        assert autoscaling.launch_configurations[0].image_id == "ami-12c6146b"
        assert autoscaling.launch_configurations[1].image_id == "ami-12c6146b"
        assert autoscaling.launch_configurations[1].name == "tester2"

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

        # AutoScaling client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        autoscaling = AutoScaling(aws_provider)
        assert len(autoscaling.groups) == 2
        assert (
            autoscaling.groups[0].arn
            == autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=["my-autoscaling-group"]
            )["AutoScalingGroups"][0]["AutoScalingGroupARN"]
        )
        assert autoscaling.groups[0].name == "my-autoscaling-group"
        assert autoscaling.groups[0].region == AWS_REGION_US_EAST_1
        assert autoscaling.groups[0].availability_zones == ["us-east-1a", "us-east-1b"]
        assert autoscaling.groups[0].tags == [
            {
                "Key": "tag_test",
                "PropagateAtLaunch": False,
                "ResourceId": "my-autoscaling-group",
                "ResourceType": "auto-scaling-group",
                "Value": "value_test",
            }
        ]
        assert autoscaling.groups[0].launch_template["LaunchTemplateName"] == "test"
        assert (
            autoscaling.groups[1].mixed_instances_policy_launch_template[
                "LaunchTemplateName"
            ]
            == "test"
        )
        assert autoscaling.groups[1].health_check_type == "ELB"
        assert autoscaling.groups[1].load_balancers == ["my-load-balancer"]
        assert autoscaling.groups[1].target_groups == [
            target_group["TargetGroups"][0]["TargetGroupArn"]
        ]

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
