from unittest import mock

from prowler.providers.aws.services.awslambda.awslambda_service import Function
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_awslambda_function_no_secrets_in_variables:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 0

    def test_function_no_variables(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
            )
        }

        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {function_name} variables."
            )
            assert result[0].resource_tags == []

    def test_function_secrets_in_keyword(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"

        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                environment={"db_password": "Tr0ub4dor3xKq9vLmZ"},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda function {function_name} variables -> Generic Password in variable db_password."
            )
            assert result[0].resource_tags == []

    def test_function_secrets_in_keyword_and_variable(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"

        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                environment={
                    "db_password": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                },
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            # Kingfisher reports both the generic keyword rule and the JWT rule
            # for the same value; their order is not guaranteed, so assert on
            # presence rather than a fixed concatenation order.
            assert result[0].status_extended.startswith(
                f"Potential secret found in Lambda function {function_name} variables -> "
            )
            assert (
                "Generic Password in variable db_password" in result[0].status_extended
            )
            assert (
                "JSON Web Token (base64url-encoded) in variable db_password"
                in result[0].status_extended
            )
            assert result[0].resource_tags == []

    def test_function_secrets_in_variables_telegram_token(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.audit_config = {"secrets_ignore_patterns": []}
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                environment={
                    # The Telegram bot-token rule is no longer enabled in
                    # Kingfisher's built-in ruleset, so a detectable JWT
                    # is used to keep this token-in-variable case meaningful.
                    "TELEGRAM_BOT_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                },
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda function {function_name} variables -> JSON Web Token (base64url-encoded) in variable TELEGRAM_BOT_TOKEN."
            )
            assert result[0].resource_tags == []

    def test_function_with_verified_secret(self):
        from prowler.lib.check.models import Severity

        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": True,
        }

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                environment={"db_password": "test-value"},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(
                    audit_config={"secrets_validate": True}
                ),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.detect_secrets_scan_batch",
                return_value={
                    0: [
                        {
                            "type": "JSON Web Token (base64url-encoded)",
                            "line_number": 2,
                            "filename": "data",
                            "hashed_secret": "x",
                            "is_verified": True,
                        }
                    ]
                },
            ) as mock_scan,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            # The check must forward secrets_validate from the config to the scan.
            assert mock_scan.call_args.kwargs.get("validate") is True
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended
            assert result[0].resource_id == function_name

    def test_function_no_secrets_in_variables(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                environment={"db_username": "test-user"},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {function_name} variables."
            )
            assert result[0].resource_tags == []

    def test_scan_failure_reports_manual_not_pass(self):
        # A scanner failure must not be treated as "no secrets found".
        from prowler.lib.utils.utils import SecretsScanError

        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.audit_config = {"secrets_ignore_patterns": []}
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime="nodejs4.3",
                environment={"db_password": "test-value"},
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.awslambda_client",
                new=lambda_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
            assert "manual review is required" in result[0].status_extended
