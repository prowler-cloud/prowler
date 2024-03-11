from re import search
from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_public_ip:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip import (
                ec2_instance_public_ip,
            )

            check = ec2_instance_public_ip()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_compliant_ec2(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": False,
                }
            ],
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip import (
                ec2_instance_public_ip,
            )

            check = ec2_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} does not have a Public IP.",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_one_ec2_with_public_ip(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": subnet.id,
                    "AssociatePublicIpAddress": True,
                }
            ],
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip.ec2_client",
            new=EC2(current_audit_info),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_public_ip.ec2_instance_public_ip import (
                ec2_instance_public_ip,
            )

            check = ec2_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} has a Public IP.",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{current_audit_info.identity.account}:instance/{instance.id}"
            )
