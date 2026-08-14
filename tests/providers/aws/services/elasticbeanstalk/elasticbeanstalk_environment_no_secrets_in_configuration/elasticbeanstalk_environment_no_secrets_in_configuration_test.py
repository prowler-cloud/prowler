from unittest import mock

from prowler.lib.check.models import Severity
from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_service import (
    Environment,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_elasticbeanstalk_environment_no_secrets_in_configuration:
    def test_no_environments(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.environments = {}
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(elasticbeanstalk_client)

        assert len(result) == 0

    def test_environment_with_no_secrets(self):
        environment = _build_environment(
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:healthreporting:system",
                    "OptionName": "SystemType",
                    "Value": "enhanced",
                },
                {
                    "Namespace": "aws:elasticbeanstalk:cloudwatch:logs",
                    "OptionName": "StreamLogs",
                    "Value": "true",
                },
            ]
        )
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.environments = {environment.arn: environment}
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(elasticbeanstalk_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No secrets found in Elastic Beanstalk environment test-env configuration settings."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "env-12345"
        assert result[0].resource_arn == environment.arn

    def test_environment_with_secrets_in_option_settings(self):
        environment = _build_environment(
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "db_pass",
                    "Value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                },
            ]
        )
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.environments = {environment.arn: environment}
        elasticbeanstalk_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }

        result = _execute_check(elasticbeanstalk_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "option setting 'aws:elasticbeanstalk:application:environment:db_pass'"
            in result[0].status_extended
        )
        # Security: the actual secret value must never appear in the report output.
        assert (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            not in result[0].status_extended
        )

    def test_environment_with_verified_secrets_annotates_critical(self):
        environment = _build_environment(
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "db_pass",
                    "Value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                },
            ]
        )
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.environments = {environment.arn: environment}
        elasticbeanstalk_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": True,
        }

        result = _execute_check_with_mocked_scan(
            elasticbeanstalk_client,
            return_value=[
                {
                    "type": "JSON Web Token",
                    "line_number": 1,
                    "is_verified": True,
                }
            ],
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == Severity.critical
        assert (
            "option setting 'aws:elasticbeanstalk:application:environment:db_pass'"
            in result[0].status_extended
        )
        assert "One or more of these secrets were confirmed to be live." in result[0].status_extended

    def test_environment_scan_error_marks_manual(self):
        environment = _build_environment(
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:healthreporting:system",
                    "OptionName": "SystemType",
                    "Value": "enhanced",
                },
            ]
        )
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.environments = {environment.arn: environment}
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check_with_mocked_scan(
            elasticbeanstalk_client,
            side_effect=SecretsScanError("Scanner failure"),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "Could not scan Elastic Beanstalk environment test-env configuration settings for secrets: Scanner failure"
            in result[0].status_extended
        )


def _build_environment(option_settings: list) -> Environment:
    env_id = "env-12345"
    env_name = "test-env"
    env_arn = f"arn:aws:elasticbeanstalk:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:environment/{env_name}"
    return Environment(
        id=env_id,
        name=env_name,
        arn=env_arn,
        region=AWS_REGION_US_EAST_1,
        application_name="test-app",
        health_reporting="basic",
        managed_platform_updates="false",
        cloudwatch_stream_logs="false",
        option_settings=option_settings,
        tags=[],
    )


def _execute_check(elasticbeanstalk_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
            elasticbeanstalk_client,
        ),
    ):
        from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
            elasticbeanstalk_environment_no_secrets_in_configuration,
        )

        check = elasticbeanstalk_environment_no_secrets_in_configuration()
        return check.execute()


def _execute_check_with_mocked_scan(
    elasticbeanstalk_client, return_value=None, side_effect=None
):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
            elasticbeanstalk_client,
        ),
    ):
        import prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration as check_module

        with mock.patch.object(
            check_module,
            "detect_secrets_scan_batch",
            return_value=return_value,
            side_effect=side_effect,
        ):
            check = check_module.elasticbeanstalk_environment_no_secrets_in_configuration()
            return check.execute()
