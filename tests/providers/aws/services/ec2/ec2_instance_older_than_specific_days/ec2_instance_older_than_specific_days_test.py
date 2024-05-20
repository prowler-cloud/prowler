import datetime
from re import search
from unittest import mock

from boto3 import resource
from dateutil.tz import tzutc
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_older_than_specific_days:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"max_ec2_instance_age_in_days": 180}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days import (
                ec2_instance_older_than_specific_days,
            )

            check = ec2_instance_older_than_specific_days()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_compliant_ec2(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"max_ec2_instance_age_in_days": 180}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days.ec2_client",
            new=EC2(aws_provider),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days import (
                ec2_instance_older_than_specific_days,
            )

            check = ec2_instance_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} is not older", result[0].status_extended
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_one_old_ec2(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"max_ec2_instance_age_in_days": 180}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days.ec2_client",
            new=EC2(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.ec2.ec2_instance_older_than_specific_days.ec2_instance_older_than_specific_days import (
                ec2_instance_older_than_specific_days,
            )

            service_client.instances[0].launch_time = datetime.datetime(
                2021, 11, 1, 17, 18, tzinfo=tzutc()
            )

            check = ec2_instance_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} is older", result[0].status_extended
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
