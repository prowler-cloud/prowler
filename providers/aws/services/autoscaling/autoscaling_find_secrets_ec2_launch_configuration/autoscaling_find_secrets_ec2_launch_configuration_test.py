from unittest import mock

from boto3 import client
from moto import mock_autoscaling

AWS_REGION = "us-east-1"


class Test_autoscaling_find_secrets_ec2_launch_configuration:
    @mock_autoscaling
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.launch_configurations = []

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.autoscaling.autoscaling_service import AutoScaling

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 0

    @mock_autoscaling
    def test_one_autoscaling_with_no_secrets(self):
        # Include launch_configurations to check
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="This is some user_data",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.autoscaling.autoscaling_service import AutoScaling

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in autoscaling tester User Data."
            )
            assert result[0].resource_id == "tester"

    @mock_autoscaling
    def test_one_autoscaling_with_secrets(self):
        # Include launch_configurations to check
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="DB_PASSWORD=foobar123",
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.autoscaling.autoscaling_service import AutoScaling

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Potential secret found in autoscaling tester User Data."
            )
            assert result[0].resource_id == "tester"

    @mock_autoscaling
    def test_one_autoscaling_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            "providers/aws/services/autoscaling/autoscaling_find_secrets_ec2_launch_configuration/fixtures/fixture",
            "r",
        )
        secrets = f.read()
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData=secrets,
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.autoscaling.autoscaling_service import AutoScaling

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Potential secret found in autoscaling tester User Data."
            )
            assert result[0].resource_id == "tester"

    @mock_autoscaling
    def test_one_launch_configurations_without_user_data(self):
        # Include launch_configurations to check
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.autoscaling.autoscaling_service import AutoScaling

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in autoscaling tester since User Data is empty."
            )
            assert result[0].resource_id == "tester"
