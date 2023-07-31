from unittest import mock

from boto3 import client, session
from moto import mock_autoscaling

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_autoscaling_find_secrets_ec2_launch_configuration:
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_autoscaling
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION)
        autoscaling_client.launch_configurations = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

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

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

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

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

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
                == "Potential secret found in autoscaling tester User Data."
            )
            assert result[0].resource_id == "tester"

    @mock_autoscaling
    def test_one_autoscaling_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            "prowler/providers/aws/services/autoscaling/autoscaling_find_secrets_ec2_launch_configuration/fixtures/fixture",
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

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

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

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        current_audit_info = self.set_mocked_audit_info()

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
                == "No secrets found in autoscaling tester since User Data is empty."
            )
            assert result[0].resource_id == "tester"
