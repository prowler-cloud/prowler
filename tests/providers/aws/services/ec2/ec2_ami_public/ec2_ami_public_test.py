from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_ami_public:
    @mock_aws
    def test_no_amis(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public import (
                ec2_ami_public,
            )

            check = ec2_ami_public()
            result = check.execute()

            assert len(result) == 0

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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public import (
                ec2_ami_public,
            )

            check = ec2_ami_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "EC2 AMI test-ami is not public."
            assert result[0].resource_id == image_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:image/{image_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public import (
                ec2_ami_public,
            )

            check = ec2_ami_public()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "EC2 AMI test-ami is currently public."
            assert result[0].resource_id == image_id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:image/{image_id}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_multiple_self_owned_amis_mixed_public_and_private(self):
        ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)

        reservation = ec2.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
        instance = reservation["Instances"][0]
        instance_id = instance["InstanceId"]

        private_image_id = ec2.create_image(
            InstanceId=instance_id,
            Name="test-private-ami",
            Description="this is a private test ami",
        )["ImageId"]
        public_image_id = ec2.create_image(
            InstanceId=instance_id,
            Name="test-public-ami",
            Description="this is a public test ami",
        )["ImageId"]

        image = resource("ec2", region_name=AWS_REGION_US_EAST_1).Image(public_image_id)
        image.modify_attribute(
            ImageId=public_image_id,
            Attribute="launchPermission",
            OperationType="add",
            UserGroups=["all"],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_ami_public.ec2_ami_public import (
                ec2_ami_public,
            )

            check = ec2_ami_public()
            result = check.execute()

            findings_by_resource_id = {
                finding.resource_id: finding for finding in result
            }

            assert len(result) == 2
            assert set(findings_by_resource_id) == {private_image_id, public_image_id}

            private_finding = findings_by_resource_id[private_image_id]
            assert private_finding.status == "PASS"
            assert (
                private_finding.status_extended
                == "EC2 AMI test-private-ami is not public."
            )
            assert (
                private_finding.resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:image/{private_image_id}"
            )
            assert private_finding.region == AWS_REGION_US_EAST_1
            assert private_finding.resource_tags == []

            public_finding = findings_by_resource_id[public_image_id]
            assert public_finding.status == "FAIL"
            assert (
                public_finding.status_extended
                == "EC2 AMI test-public-ami is currently public."
            )
            assert (
                public_finding.resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:image/{public_image_id}"
            )
            assert public_finding.region == AWS_REGION_US_EAST_1
            assert public_finding.resource_tags == []
