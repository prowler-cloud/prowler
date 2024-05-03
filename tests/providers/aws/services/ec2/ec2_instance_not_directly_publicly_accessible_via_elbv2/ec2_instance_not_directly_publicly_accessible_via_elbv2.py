from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_not_directly_publicly_accessible_via_elbv2:
    @mock_aws
    def test_no_elbsv2(self):
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers.elbv2_client",
            new=ELBv2(
                set_mocked_aws_provider([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.elbv2.elbv2_insecure_ssl_ciphers.elbv2_insecure_ssl_ciphers import (
                elbv2_insecure_ssl_ciphers,
            )

            check = elbv2_insecure_ssl_ciphers()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_behind_public_elbv2(self):
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
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="instance",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        security_group_instance = ec2.create_security_group(
            GroupName="sg01_instance",
            Description="Test security group for EC2 instance",
        )

        iam = client("iam", "us-west-1")
        profile_name = "fake_profile"
        iam.create_instance_profile(
            InstanceProfileName=profile_name,
        )
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": False,
                    "Groups": [security_group_instance.id],
                }
            ],
        )[0]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": instance.id},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2 import (
                ec2_instance_not_directly_publicly_accessible_via_elbv2,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elbv2()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert search(
                "is behind a internet facing load balancer",
                findings[0].status_extended,
            )

    @mock_aws
    def test_ec2_behind_private_elbv2(self):
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
            HealthCheckProtocol="HTTP",
            HealthCheckPath="/",
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=5,
            UnhealthyThresholdCount=2,
            TargetType="instance",
        )["TargetGroups"][0]

        target_group_arn = target_group["TargetGroupArn"]

        security_group_instance = ec2.create_security_group(
            GroupName="sg01_instance",
            Description="Test security group for EC2 instance",
        )

        iam = client("iam", "us-west-1")
        profile_name = "fake_profile"
        iam.create_instance_profile(
            InstanceProfileName=profile_name,
        )
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": False,
                    "Groups": [security_group_instance.id],
                }
            ],
        )[0]

        conn.register_targets(
            TargetGroupArn=target_group_arn,
            Targets=[
                {"Id": instance.id},
            ],
        )

        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2.elbv2_client",
            new=ELBv2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elbv2.ec2_instance_not_directly_publicly_accessible_via_elbv2 import (
                ec2_instance_not_directly_publicly_accessible_via_elbv2,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elbv2()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert search(
                "is not behind a internet facing load balancer.",
                findings[0].status_extended,
            )