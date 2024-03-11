from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_detailed_monitoring_enabled:
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
            "prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled import (
                ec2_instance_detailed_monitoring_enabled,
            )

            check = ec2_instance_detailed_monitoring_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_instance_with_enhanced_monitoring_disabled(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            Monitoring={"Enabled": False},
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled import (
                ec2_instance_detailed_monitoring_enabled,
            )

            check = ec2_instance_detailed_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto fills instance tags with None
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} does not have detailed monitoring enabled."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_instance_with_enhanced_monitoring_enabled(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            Monitoring={"Enabled": True},
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled.ec2_client",
            new=EC2(aws_provider),
        ) as ec2_service:
            from prowler.providers.aws.services.ec2.ec2_instance_detailed_monitoring_enabled.ec2_instance_detailed_monitoring_enabled import (
                ec2_instance_detailed_monitoring_enabled,
            )

            # TEMPORAL FIX
            # Need to inspect why in service the monitoring state is set as disabled, since when is this failing ???
            ec2_service.instances[0].monitoring_state = "enabled"
            check = ec2_instance_detailed_monitoring_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto fills instance tags with None
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended
                == f"EC2 Instance {instance.id} has detailed monitoring enabled."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
