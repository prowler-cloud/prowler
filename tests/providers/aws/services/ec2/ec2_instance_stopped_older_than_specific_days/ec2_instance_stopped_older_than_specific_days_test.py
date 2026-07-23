from datetime import datetime, timedelta, timezone
from re import search
from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_instance_stopped_older_than_specific_days:
    @mock_aws
    def test_ec2_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        aws_provider._audit_config = {"max_ec2_instance_stopped_days": 30}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days import (
                ec2_instance_stopped_older_than_specific_days,
            )

            check = ec2_instance_stopped_older_than_specific_days()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_running_ec2(self):
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
        aws_provider._audit_config = {"max_ec2_instance_stopped_days": 30}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days import (
                ec2_instance_stopped_older_than_specific_days,
            )

            check = ec2_instance_stopped_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags is None
            assert search(
                f"EC2 Instance {instance.id} is not stopped",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_stopped_ec2_within_threshold(self):
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
        aws_provider._audit_config = {"max_ec2_instance_stopped_days": 30}

        # Boundary: stopped exactly 30 days ago must remain PASS
        # (threshold is exclusive: time_stopped > timedelta(days=30)).
        fixed_now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        recent_stop = fixed_now - timedelta(days=30)
        stop_reason = recent_stop.strftime("User initiated (%Y-%m-%d %H:%M:%S GMT)")

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.ec2_client",
                new=EC2(aws_provider),
            ) as service_client,
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.datetime"
            ) as mock_datetime,
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days import (
                ec2_instance_stopped_older_than_specific_days,
            )

            mock_datetime.now.return_value = fixed_now
            mock_datetime.strptime = datetime.strptime

            service_client.instances[0].state = "stopped"
            service_client.instances[0].state_transition_reason = stop_reason

            check = ec2_instance_stopped_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert search(
                f"EC2 Instance {instance.id} has not been stopped longer than",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_stopped_ec2_older_than_threshold(self):
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
        aws_provider._audit_config = {"max_ec2_instance_stopped_days": 30}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.ec2_client",
                new=EC2(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days import (
                ec2_instance_stopped_older_than_specific_days,
            )

            service_client.instances[0].state = "stopped"
            service_client.instances[0].state_transition_reason = (
                "User initiated (2021-11-01 17:18:00 GMT)"
            )

            check = ec2_instance_stopped_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert search(
                f"EC2 Instance {instance.id} has been stopped longer than",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )

    @mock_aws
    def test_stopped_ec2_unknown_stop_time(self):
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
        aws_provider._audit_config = {"max_ec2_instance_stopped_days": 30}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days.ec2_client",
                new=EC2(aws_provider),
            ) as service_client,
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_stopped_older_than_specific_days.ec2_instance_stopped_older_than_specific_days import (
                ec2_instance_stopped_older_than_specific_days,
            )

            service_client.instances[0].state = "stopped"
            service_client.instances[0].state_transition_reason = ""

            check = ec2_instance_stopped_older_than_specific_days()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert search(
                f"EC2 Instance {instance.id} is stopped but stop time could not be determined",
                result[0].status_extended,
            )
            assert result[0].resource_id == instance.id
