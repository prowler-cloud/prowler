from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_autoscaling_group_multiple_az:
    @mock_aws
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.groups = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az import (
                autoscaling_group_multiple_az,
            )

            check = autoscaling_group_multiple_az()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_groups_with_multi_az(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_group_name = "my-autoscaling-group"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=autoscaling_group_name,
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
        )

        autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az import (
                autoscaling_group_multiple_az,
            )

            check = autoscaling_group_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Autoscaling group {autoscaling_group_name} has multiple availability zones."
            )
            assert result[0].resource_id == autoscaling_group_name
            assert result[0].resource_arn == autoscaling_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_groups_with_single_az(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_group_name = "my-autoscaling-group"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=autoscaling_group_name,
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a"],
        )

        autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az import (
                autoscaling_group_multiple_az,
            )

            check = autoscaling_group_multiple_az()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Autoscaling group {autoscaling_group_name} has only one availability zones."
            )
            assert result[0].resource_id == autoscaling_group_name
            assert result[0].resource_tags == []
            assert result[0].resource_arn == autoscaling_group_arn

    @mock_aws
    def test_groups_witd_and_without(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_group_name_1 = "asg-multiple"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="asg-multiple",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
        )
        autoscaling_group_arn_1 = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name_1]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        autoscaling_group_name_2 = "asg-single"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="asg-single",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a"],
        )
        autoscaling_group_arn_2 = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name_2]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_az.autoscaling_group_multiple_az import (
                autoscaling_group_multiple_az,
            )

            check = autoscaling_group_multiple_az()
            result = check.execute()

            assert len(result) == 2
            for check in result:
                if check.resource_id == autoscaling_group_name_1:
                    assert check.status == "PASS"
                    assert (
                        check.status_extended
                        == f"Autoscaling group {autoscaling_group_name_1} has multiple availability zones."
                    )
                    assert check.resource_arn == autoscaling_group_arn_1
                    assert check.resource_tags == []
                    assert check.region == AWS_REGION_US_EAST_1
                if check.resource_id == autoscaling_group_name_2:
                    assert check.status == "FAIL"
                    assert (
                        check.status_extended
                        == f"Autoscaling group {autoscaling_group_name_2} has only one availability zones."
                    )
                    assert check.resource_tags == []
                    assert check.resource_arn == autoscaling_group_arn_2
                    assert check.region == AWS_REGION_US_EAST_1
