from os import path
from pathlib import Path
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"


class Test_autoscaling_find_secrets_ec2_launch_configuration:
    @mock_aws
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.launch_configurations = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_autoscaling_with_no_secrets(self):
        # Include launch_configurations to check
        launch_configuration_name = "tester"
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName=launch_configuration_name,
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="This is some user_data",
        )
        launch_configuration_arn = autoscaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )["LaunchConfigurations"][0]["LaunchConfigurationARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in autoscaling {launch_configuration_name} User Data."
            )
            assert result[0].resource_id == launch_configuration_name
            assert result[0].resource_arn == launch_configuration_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_autoscaling_with_secrets(self):
        # Include launch_configurations to check
        launch_configuration_name = "tester"
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName=launch_configuration_name,
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData="DB_PASSWORD=foobar123",
        )
        launch_configuration_arn = autoscaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )["LaunchConfigurations"][0]["LaunchConfigurationARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in autoscaling {launch_configuration_name} User Data."
            )
            assert result[0].resource_id == launch_configuration_name
            assert result[0].resource_arn == launch_configuration_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_autoscaling_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "r",
        )
        secrets = f.read()
        launch_configuration_name = "tester"
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData=secrets,
        )
        launch_configuration_arn = autoscaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )["LaunchConfigurations"][0]["LaunchConfigurationARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in autoscaling {launch_configuration_name} User Data."
            )
            assert result[0].resource_id == launch_configuration_name
            assert result[0].resource_arn == launch_configuration_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_configurations_without_user_data(self):
        # Include launch_configurations to check
        launch_configuration_name = "tester"
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName=launch_configuration_name,
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        launch_configuration_arn = autoscaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )["LaunchConfigurations"][0]["LaunchConfigurationARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in autoscaling {launch_configuration_name} since User Data is empty."
            )
            assert result[0].resource_id == launch_configuration_name
            assert result[0].resource_arn == launch_configuration_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_autoscaling_file_with_secrets_gzip(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture.gz",
            "rb",
        )

        secrets = f.read()
        launch_configuration_name = "tester"
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="tester",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
            UserData=secrets,
        )
        launch_configuration_arn = autoscaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )["LaunchConfigurations"][0]["LaunchConfigurationARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_client",
            new=AutoScaling(current_audit_info),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_find_secrets_ec2_launch_configuration.autoscaling_find_secrets_ec2_launch_configuration import (
                autoscaling_find_secrets_ec2_launch_configuration,
            )

            check = autoscaling_find_secrets_ec2_launch_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in autoscaling {launch_configuration_name} User Data."
            )
            assert result[0].resource_id == launch_configuration_name
            assert result[0].resource_arn == launch_configuration_arn
            assert result[0].region == AWS_REGION_US_EAST_1
