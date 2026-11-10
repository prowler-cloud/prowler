from unittest import mock

import pytest

from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_service import (
    Environment,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_php_platform_updated.elasticbeanstalk_environment_php_platform_updated"
ENV_ARN = f"arn:aws:elasticbeanstalk:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:environment/test-app/test-env"


def _environment(solution_stack_name="", platform_arn=""):
    return Environment(
        id="e-abc123",
        name="test-env",
        arn=ENV_ARN,
        region=AWS_REGION_EU_WEST_1,
        application_name="test-app",
        solution_stack_name=solution_stack_name,
        platform_arn=platform_arn,
    )


def _run_check(environments, audit_config=None):
    elasticbeanstalk_client = mock.MagicMock()
    elasticbeanstalk_client.environments = environments
    elasticbeanstalk_client.audit_config = audit_config or {}

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_EU_WEST_1]),
        ),
        mock.patch(
            f"{CHECK_PATH}.elasticbeanstalk_client", new=elasticbeanstalk_client
        ),
    ):
        from prowler.providers.aws.services.elasticbeanstalk.elasticbeanstalk_environment_php_platform_updated.elasticbeanstalk_environment_php_platform_updated import (
            elasticbeanstalk_environment_php_platform_updated,
        )

        return elasticbeanstalk_environment_php_platform_updated().execute()


class Test_elasticbeanstalk_environment_php_platform_updated:
    def test_no_environments(self):
        assert len(_run_check({})) == 0

    def test_non_php_environment_is_skipped(self):
        environments = {
            ENV_ARN: _environment("64bit Amazon Linux 2023 v4.7.3 running Python 3.12")
        }
        assert len(_run_check(environments)) == 0

    def test_environment_without_stack_is_skipped(self):
        assert len(_run_check({ENV_ARN: _environment()})) == 0

    @pytest.mark.parametrize(
        "solution_stack_name,expected_status,expected_message",
        [
            (
                "64bit Amazon Linux 2023 v4.13.13 running PHP 8.4",
                "PASS",
                "Elastic Beanstalk environment test-env runs PHP 8.4 on platform version 4.13.13, which includes the fixed PHP release.",
            ),
            (
                "64bit Amazon Linux 2023 v4.14.0 running PHP 8.2",
                "PASS",
                "Elastic Beanstalk environment test-env runs PHP 8.2 on platform version 4.14.0, which includes the fixed PHP release.",
            ),
            (
                "64bit Amazon Linux 2023 v4.13.12 running PHP 8.5",
                "FAIL",
                "Elastic Beanstalk environment test-env runs PHP 8.5 on platform version 4.13.12, below the minimum fixed platform version 4.13.13.",
            ),
            (
                "64bit Amazon Linux 2023 v4.9.2 running PHP 8.3",
                "FAIL",
                "Elastic Beanstalk environment test-env runs PHP 8.3 on platform version 4.9.2, below the minimum fixed platform version 4.13.13.",
            ),
            (
                "64bit Amazon Linux 2023 v4.13.13 running PHP 8.1",
                "FAIL",
                "Elastic Beanstalk environment test-env runs PHP 8.1, a branch that no longer receives security fixes (minimum supported branch is 8.2).",
            ),
            (
                "64bit Amazon Linux 2 v3.9.5 running PHP 8.2",
                "FAIL",
                "Elastic Beanstalk environment test-env runs PHP 8.2 on platform '64bit Amazon Linux 2 v3.9.5 running PHP 8.2', a platform family without fixed PHP releases; migrate it to a PHP 8.2 Amazon Linux 2023 platform version 4.13.13 or newer.",
            ),
        ],
    )
    def test_php_environment(
        self, solution_stack_name, expected_status, expected_message
    ):
        result = _run_check({ENV_ARN: _environment(solution_stack_name)})
        assert len(result) == 1
        assert result[0].status == expected_status
        assert result[0].status_extended == expected_message
        assert result[0].resource_id == "e-abc123"
        assert result[0].resource_arn == ENV_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_platform_arn_fallback(self):
        environments = {
            ENV_ARN: _environment(
                platform_arn=f"arn:aws:elasticbeanstalk:{AWS_REGION_EU_WEST_1}::platform/PHP 8.3 running on 64bit Amazon Linux 2023/4.13.13"
            )
        }
        result = _run_check(environments)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_custom_minimums(self):
        environments = {
            ENV_ARN: _environment("64bit Amazon Linux 2023 v4.13.13 running PHP 8.3")
        }
        result = _run_check(
            environments,
            {
                "elasticbeanstalk_php_min_branch": "8.4",
                "elasticbeanstalk_php_min_platform_version": "4.13.13",
            },
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Elastic Beanstalk environment test-env runs PHP 8.3, a branch that no longer receives security fixes (minimum supported branch is 8.4)."
        )
