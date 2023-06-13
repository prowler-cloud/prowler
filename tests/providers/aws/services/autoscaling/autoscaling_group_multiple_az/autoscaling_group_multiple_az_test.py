from unittest import mock

from boto3 import client, session
from moto import mock_autoscaling

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_autoscaling_group_multiple_az:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )

        return audit_info

    @mock_autoscaling
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.groups = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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

    @mock_autoscaling
    def test_groups_with_multi_az(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                == "Autoscaling group my-autoscaling-group has multiple availability zones."
            )
            assert result[0].resource_id == "my-autoscaling-group"
            assert result[0].resource_tags == []

    @mock_autoscaling
    def test_groups_with_single_az(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a"],
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                == "Autoscaling group my-autoscaling-group has only one availability zones."
            )
            assert result[0].resource_id == "my-autoscaling-group"
            assert result[0].resource_tags == []

    @mock_autoscaling
    def test_groups_witd_and_without(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="asg-multiple",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
        )
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="asg-single",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a"],
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                if check.resource_id == "asg-multiple":
                    assert check.status == "PASS"
                    assert (
                        check.status_extended
                        == "Autoscaling group asg-multiple has multiple availability zones."
                    )
                    assert check.resource_tags == []
                if check.resource_id == "asg-single":
                    assert check.status == "FAIL"
                    assert (
                        check.status_extended
                        == "Autoscaling group asg-single has only one availability zones."
                    )
                    assert check.resource_tags == []
