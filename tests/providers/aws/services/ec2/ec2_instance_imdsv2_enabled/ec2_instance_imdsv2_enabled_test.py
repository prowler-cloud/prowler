from re import search
from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_imdsv2_enabled:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_compliant_ec2(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
            },
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled.ec2_client",
            new=EC2(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            service_client.instances[0].http_endpoint = "enabled"
            service_client.instances[0].http_tokens = "required"

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto fills instance tags with None
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} has IMDSv2 enabled and required",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_one_uncompliant_ec2_metadata_server_disabled(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={
                "HttpTokens": "optional",
                "HttpEndpoint": "disabled",
            },
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled.ec2_client",
            new=EC2(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            service_client.instances[0].http_endpoint = "disabled"
            service_client.instances[0].http_tokens = "optional"

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto fills instance tags with None
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} has metadata service disabled."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_one_uncompliant_ec2_metadata_server_enabled(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled",
            },
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled.ec2_client",
            new=EC2(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.ec2.ec2_instance_imdsv2_enabled.ec2_instance_imdsv2_enabled import (
                ec2_instance_imdsv2_enabled,
            )

            service_client.instances[0].http_endpoint = "enabled"
            service_client.instances[0].http_tokens = "optional"

            check = ec2_instance_imdsv2_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto fills instance tags with None
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} has IMDSv2 disabled or not required."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
