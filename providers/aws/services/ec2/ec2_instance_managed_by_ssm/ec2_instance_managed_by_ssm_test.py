from re import search
from unittest import mock

from boto3 import resource
from moto import mock_ec2, mock_ssm

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_managed_by_ssm:
    @mock_ssm
    @mock_ec2
    def test_ec2_no_instances(self):

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2
        from providers.aws.services.ssm.ssm_service import SSM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ec2_client",
            new=EC2(current_audit_info),
        ):
            with mock.patch(
                "providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ssm_client",
                new=SSM(current_audit_info),
            ):
                # Test Check
                from providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm import (
                    ec2_instance_managed_by_ssm,
                )

                check = ec2_instance_managed_by_ssm()
                result = check.execute()

                assert len(result) == 0

    @mock_ssm
    @mock_ec2
    def test_one_unmanaged_ec2_by_ssm(self):

        ec2 = resource("ec2", region_name=AWS_REGION)
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

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2
        from providers.aws.services.ssm.ssm_service import SSM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ec2_client",
            new=EC2(current_audit_info),
        ):
            with mock.patch(
                "providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm.ssm_client",
                new=SSM(current_audit_info),
            ):
                # Test Check
                from providers.aws.services.ec2.ec2_instance_managed_by_ssm.ec2_instance_managed_by_ssm import (
                    ec2_instance_managed_by_ssm,
                )

                check = ec2_instance_managed_by_ssm()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "is not managed by Systems Manager",
                    result[0].status_extended,
                )
                assert result[0].resource_id == instance.id
