from unittest import mock

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
    def test_environment_configuration_with_secrets(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}
        eb_env_arn = f"arn:partition:elasticbeanstalk:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:environment/production"

        environment = Environment(
            id="e-vbxmknpy2z",
            name="production",
            arn=eb_env_arn,
            region=AWS_REGION_US_EAST_1,
            application_name="test-app",
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "JSON_WEB_TOKEN",
                    "Value": "test-token",
                },
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "MONGODB_URI",
                    "Value": "test-mongodb-uri",
                },
            ],
        )
        elasticbeanstalk_client.environments = {eb_env_arn: environment}

        mocked_scan_results = {
            (
                eb_env_arn,
                "aws:elasticbeanstalk:application:environment",
                "JSON_WEB_TOKEN",
            ): [
                {
                    "filename": "payload",
                    "line_number": 1,
                    "type": "SecretKeyword",
                    "hashed_secret": "mocked-hash",
                    "is_verified": False,
                }
            ],
            (
                eb_env_arn,
                "aws:elasticbeanstalk:application:environment",
                "MONGODB_URI",
            ): [
                {
                    "filename": "payload",
                    "line_number": 1,
                    "type": "SecretKeyword",
                    "hashed_secret": "mocked-hash-2",
                    "is_verified": False,
                }
            ],
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
                new=elasticbeanstalk_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.detect_secrets_scan_batch",
                return_value=mocked_scan_results,
            ),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
                elasticbeanstalk_environment_no_secrets_in_configuration,
            )

            check = elasticbeanstalk_environment_no_secrets_in_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert environment.name in result[0].status_extended
            assert "JSON_WEB_TOKEN" in result[0].status_extended
            assert "MONGODB_URI" in result[0].status_extended

    def test_environment_configuration_without_secrets(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}
        eb_env_arn = f"arn:partition:elasticbeanstalk:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:environment/staging"

        environment = Environment(
            id="e-icsgecu3wf",
            name="staging",
            arn=eb_env_arn,
            region=AWS_REGION_US_EAST_1,
            application_name="test-app",
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "LOG_LEVEL",
                    "Value": "INFO",
                },
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "SystemType",
                    "Value": "enhanced",
                },
            ],
        )
        elasticbeanstalk_client.environments = {eb_env_arn: environment}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
                new=elasticbeanstalk_client,
            ),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
                elasticbeanstalk_environment_no_secrets_in_configuration,
            )

            check = elasticbeanstalk_environment_no_secrets_in_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Elastic Beanstalk environment configuration for {environment.name} environment."
            )

    def test_environment_configuration_scan_error(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}
        eb_env_arn = f"arn:partition:elasticbeanstalk:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:environment/testing"

        environment = Environment(
            id="e-mz7paq4pqp",
            name="testing",
            arn=eb_env_arn,
            region=AWS_REGION_US_EAST_1,
            application_name="test-app",
            option_settings=[
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "DB_SSL_ENABLED",
                    "Value": "true",
                },
                {
                    "Namespace": "aws:elasticbeanstalk:application:environment",
                    "OptionName": "CACHE_TTL",
                    "Value": "300",
                },
            ],
        )
        elasticbeanstalk_client.environments = {eb_env_arn: environment}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
                new=elasticbeanstalk_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
                elasticbeanstalk_environment_no_secrets_in_configuration,
            )

            check = elasticbeanstalk_environment_no_secrets_in_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                f"Could not scan Elastic Beanstalk environment configuration for {environment.name} environment"
                in result[0].status_extended
            )

    def test_no_environment(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}

        elasticbeanstalk_client.environments = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
                new=elasticbeanstalk_client,
            ),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
                elasticbeanstalk_environment_no_secrets_in_configuration,
            )

            check = elasticbeanstalk_environment_no_secrets_in_configuration()
            result = check.execute()

            assert len(result) == 0

    def test_environment_option_settings_is_none(self):
        elasticbeanstalk_client = mock.MagicMock()
        elasticbeanstalk_client.audit_config = {"secrets_ignore_patterns": []}
        eb_env_arn = f"arn:partition:elasticbeanstalk:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:environment/dev"

        environment = Environment(
            id="e-c4f7hda2nb",
            name="dev",
            arn=eb_env_arn,
            region=AWS_REGION_US_EAST_1,
            application_name="test-app",
            option_settings=None,
        )
        elasticbeanstalk_client.environments = {eb_env_arn: environment}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_client",
                new=elasticbeanstalk_client,
            ),
        ):
            from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_no_secrets_in_configuration.elasticbeanstalk_environment_no_secrets_in_configuration import (
                elasticbeanstalk_environment_no_secrets_in_configuration,
            )

            check = elasticbeanstalk_environment_no_secrets_in_configuration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"No option settings found for Elastic Beanstalk {environment.name} environment; manual review is required."
            )
