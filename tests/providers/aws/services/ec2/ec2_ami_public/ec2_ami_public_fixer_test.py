from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_ami_public_fixer:
    @mock_aws
    def test_one_private_ami(self):
        ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)

        reservation = ec2.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
        instance = reservation["Instances"][0]
        instance_id = instance["InstanceId"]

        image_id = ec2.create_image(
            InstanceId=instance_id, Name="test-ami", Description="this is a test ami"
        )["ImageId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer import (
                fixer,
            )

            assert fixer(image_id, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_one_public_ami(self):
        ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)

        reservation = ec2.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
        instance = reservation["Instances"][0]
        instance_id = instance["InstanceId"]

        image_id = ec2.create_image(
            InstanceId=instance_id, Name="test-ami", Description="this is a test ami"
        )["ImageId"]

        image = resource("ec2", region_name="us-east-1").Image(image_id)
        ADD_GROUP_ARGS = {
            "ImageId": image_id,
            "Attribute": "launchPermission",
            "OperationType": "add",
            "UserGroups": ["all"],
        }
        image.modify_attribute(**ADD_GROUP_ARGS)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer import (
                fixer,
            )

            assert fixer(image_id, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_one_public_ami_error(self):
        ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)

        reservation = ec2.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
        instance = reservation["Instances"][0]
        instance_id = instance["InstanceId"]

        image_id = ec2.create_image(
            InstanceId=instance_id, Name="test-ami", Description="this is a test ami"
        )["ImageId"]

        image = resource("ec2", region_name="us-east-1").Image(image_id)
        ADD_GROUP_ARGS = {
            "ImageId": image_id,
            "Attribute": "launchPermission",
            "OperationType": "add",
            "UserGroups": ["all"],
        }
        image.modify_attribute(**ADD_GROUP_ARGS)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public_fixer import (
                fixer,
            )

            assert not fixer("image_id_non_existing", AWS_REGION_US_EAST_1)
