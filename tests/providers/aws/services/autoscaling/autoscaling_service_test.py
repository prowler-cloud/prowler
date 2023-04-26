from base64 import b64decode

from boto3 import client, session
from moto import mock_autoscaling

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.autoscaling.autoscaling_service import AutoScaling

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_AutoScaling_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test AutoScaling Service
    @mock_autoscaling
    def test_service(self):
        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        assert autoscaling.service == "autoscaling"

    # Test AutoScaling Client
    @mock_autoscaling
    def test_client(self):
        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        for regional_client in autoscaling.regional_clients.values():
            assert regional_client.__class__.__name__ == "AutoScaling"

    # Test AutoScaling Session
    @mock_autoscaling
    def test__get_session__(self):
        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        assert autoscaling.session.__class__.__name__ == "Session"

    # Test AutoScaling Session
    @mock_autoscaling
    def test_audited_account(self):
        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        assert autoscaling.audited_account == AWS_ACCOUNT_NUMBER

    # Test AutoScaling Get APIs
    @mock_autoscaling
    def test__describe_launch_configurations__(self):
        # Generate AutoScaling Client
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        # Create AutoScaling API
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester1",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="DB_PASSWORD=foobar123",
        )
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester2",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        assert len(autoscaling.launch_configurations) == 2
        assert autoscaling.launch_configurations[0].name == "tester1"
        assert (
            b64decode(autoscaling.launch_configurations[0].user_data).decode("utf-8")
            == "DB_PASSWORD=foobar123"
        )
        assert autoscaling.launch_configurations[0].image_id == "ami-12c6146b"
        assert autoscaling.launch_configurations[1].image_id == "ami-12c6146b"
        assert autoscaling.launch_configurations[1].name == "tester2"

    # Test Describe Auto Scaling Groups
    @mock_autoscaling
    def test__describe_auto_scaling_groups__(self):
        # Generate AutoScaling Client
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        asg = autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName="my-autoscaling-group",
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
            Tags=[
                {
                    "Key": "tag_test",
                    "Value": "value_test",
                },
            ],
        )

        # AutoScaling client for this test class
        audit_info = self.set_mocked_audit_info()
        autoscaling = AutoScaling(audit_info)
        print("asg", asg)
        assert len(autoscaling.groups) == 1
        # create_auto_scaling_group doesn't return the ARN, can't check it
        # assert autoscaling.groups[0].arn ==
        assert autoscaling.groups[0].name == "my-autoscaling-group"
        assert autoscaling.groups[0].region == AWS_REGION
        assert autoscaling.groups[0].availability_zones == ["us-east-1a", "us-east-1b"]
        assert autoscaling.groups[0].tags == [
            {
                "Key": "tag_test",
                "PropagateAtLaunch": False,
                "ResourceId": "my-autoscaling-group",
                "ResourceType": "auto-scaling-group",
                "Value": "value_test",
            }
        ]
