from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_not_directly_publicly_accessible_via_elb:
    @mock_aws
    def test_ec2_no_public_elbs(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb import (
                ec2_instance_not_directly_publicly_accessible_via_elb,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elb()
            findings = check.execute()

            assert len(findings) == 0

    @mock_aws
    def test_ec2_behind_public_elb(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )

        security_group_instance = ec2.create_security_group(
            GroupName="sg01_instance",
            Description="Test security group for EC2 instance",
        )

        iam = client("iam", "us-west-1")
        profile_name = "fake_profile"
        _ = iam.create_instance_profile(
            InstanceProfileName=profile_name,
        )
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
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
                    "Groups": [
                        security_group_instance.id
                    ],  # Assign instance to its own security group
                }
            ],
        )[0]

        # Register the instance with the load balancer
        elb.register_instances_with_load_balancer(
            LoadBalancerName="my-lb",
            Instances=[
                {"InstanceId": instance.id},
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.elb.elb_service import ELB

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.elb_client",
            new=ELB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb import (
                ec2_instance_not_directly_publicly_accessible_via_elb,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elb()
            findings = check.execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert (
                findings[0].status_extended
                == f"EC2 Instance {instance.id} is behind a internet facing classic load balancer my-lb.us-east-1.elb.amazonaws.com."
            )

    @mock_aws
    def test_ec2_behind_internal_elb(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        security_group_instance = ec2.create_security_group(
            GroupName="sg01_instance",
            Description="Test security group for EC2 instance",
        )

        iam = client("iam", "us-west-1")
        profile_name = "fake_profile"
        _ = iam.create_instance_profile(
            InstanceProfileName=profile_name,
        )
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
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
                    "Groups": [
                        security_group_instance.id
                    ],  # Assign instance to its own security group
                }
            ],
        )[0]

        # Register the instance with the load balancer
        elb.register_instances_with_load_balancer(
            LoadBalancerName="my-lb",
            Instances=[
                {"InstanceId": instance.id},
            ],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.elb.elb_service import ELB

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.elb_client",
            new=ELB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb import (
                ec2_instance_not_directly_publicly_accessible_via_elb,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elb()
            findings = check.execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert (
                findings[0].status_extended
                == f"EC2 Instance {instance.id} is not behind a internet facing classic load balancer."
            )

    @mock_aws
    def test_two_ec2_behind_public_elb(self):
        elb = client("elb", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[AWS_REGION_EU_WEST_1_AZA],
            Scheme="internet-facing",
            SecurityGroups=[security_group.id],
        )

        security_group_instance = ec2.create_security_group(
            GroupName="sg01_instance",
            Description="Test security group for EC2 instance",
        )

        iam = client("iam", "us-west-1")
        profile_name = "fake_profile"
        iam.create_instance_profile(
            InstanceProfileName=profile_name,
        )
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        # Create two EC2 instances
        instances = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=2,
            MaxCount=2,
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": False,
                    "Groups": [
                        security_group_instance.id
                    ],  # Assign instance to its own security group
                }
            ],
        )

        # Register the instances with the load balancer
        elb.register_instances_with_load_balancer(
            LoadBalancerName="my-lb",
            Instances=[{"InstanceId": instance.id} for instance in instances],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.elb.elb_service import ELB

        current_audit_info = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb.elb_client",
            new=ELB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_not_directly_publicly_accessible_via_elb.ec2_instance_not_directly_publicly_accessible_via_elb import (
                ec2_instance_not_directly_publicly_accessible_via_elb,
            )

            check = ec2_instance_not_directly_publicly_accessible_via_elb()
            findings = check.execute()
            assert len(findings) == 2
            assert findings[0].status == "FAIL"
            assert (
                findings[0].status_extended
                == f"EC2 Instance {instances[0].id} is behind a internet facing classic load balancer my-lb.us-east-1.elb.amazonaws.com."
            )
            assert findings[1].status == "FAIL"
            assert (
                findings[1].status_extended
                == f"EC2 Instance {instances[1].id} is behind a internet facing classic load balancer my-lb.us-east-1.elb.amazonaws.com."
            )