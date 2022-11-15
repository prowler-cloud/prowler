from re import search
from unittest import mock

from providers.aws.services.ec2.ec2_service import Instance

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_imdsv2_enabled:
    def test_ec2_no_instances(self):

        ec2_client = mock.MagicMock
        ec2_client.instances = []

        with mock.patch(
            "providers.aws.services.ec2.ec2_service.EC2",
            ec2_client,
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_compliant_ec2(self):
        ec2_client = mock.MagicMock
        ec2_client.instances = [
            Instance(
                "instance-id",
                "running",
                AWS_REGION,
                "t2.micro",
                EXAMPLE_AMI_ID,
                None,
                None,
                None,
                None,
                None,
                "required",
                "enabled",
                None,
            )
        ]

        with mock.patch(
            "providers.aws.services.ec2.ec2_service.EC2",
            ec2_client,
        ):
            from providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has IMDSv2 enabled and required", result[0].status_extended)
            assert result[0].resource_id == "instance-id"

    def test_one_ec2_with_imdsv1(self):
        ec2_client = mock.MagicMock
        ec2_client.instances = [
            Instance(
                "instance-id",
                "running",
                AWS_REGION,
                "t2.micro",
                EXAMPLE_AMI_ID,
                None,
                None,
                None,
                None,
                None,
                "optional",
                "disabled",
                None,
            )
        ]

        with mock.patch(
            "providers.aws.services.ec2.ec2_service.EC2",
            ec2_client,
        ):
            from providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has IMDSv2 disabled or not required", result[0].status_extended
            )
            assert result[0].resource_id == "instance-id"
