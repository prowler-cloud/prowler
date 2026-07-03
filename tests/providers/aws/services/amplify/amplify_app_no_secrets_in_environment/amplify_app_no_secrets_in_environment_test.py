from unittest import mock

from prowler.providers.aws.services.amplify.amplify_service import App, Branch
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Construct the fake JWT token using string concatenation to avoid detection by secret scanners.
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


class Test_amplify_app_no_secrets_in_environment:
    def test_no_apps(self):
        amplify_client = mock.MagicMock()
        amplify_client.apps = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(amplify_client)

        assert len(result) == 0

    def test_app_with_no_secrets(self):
        app = _build_app(
            environment_variables={"key1": "val1"},
            build_spec="version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - echo hello",
            branches=[
                Branch(
                    name="main",
                    arn=f"arn:aws:amplify:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apps/app-12345/branches/main",
                    environment_variables={"branch_key": "branch_val"},
                )
            ],
        )
        amplify_client = mock.MagicMock()
        amplify_client.apps = {app.arn: app}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(amplify_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "No secrets found in Amplify app test-app environment variables or build settings."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "app-12345"
        assert result[0].resource_arn == app.arn

    def test_app_with_secrets_in_app_variables(self):
        app = _build_app(
            environment_variables={"db_pass": FAKE_JWT},
            build_spec="",
            branches=[],
        )
        amplify_client = mock.MagicMock()
        amplify_client.apps = {app.arn: app}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(amplify_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "app environment variable 'db_pass'" in result[0].status_extended

    def test_app_with_secrets_in_branch_variables(self):
        app = _build_app(
            environment_variables={},
            build_spec="",
            branches=[
                Branch(
                    name="dev",
                    arn=f"arn:aws:amplify:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apps/app-12345/branches/dev",
                    environment_variables={"api_key": FAKE_JWT},
                )
            ],
        )
        amplify_client = mock.MagicMock()
        amplify_client.apps = {app.arn: app}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(amplify_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "branch 'dev' environment variable 'api_key'" in result[0].status_extended
        )

    def test_app_with_secrets_in_build_spec(self):
        app = _build_app(
            environment_variables={},
            build_spec=f"version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - export JWT={FAKE_JWT}",
            branches=[],
        )
        amplify_client = mock.MagicMock()
        amplify_client.apps = {app.arn: app}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(amplify_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "app buildSpec line 6" in result[0].status_extended

    def test_app_scan_error_marks_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        app = _build_app(
            environment_variables={"key1": "val1"},
            build_spec="version: 1",
            branches=[],
        )
        amplify_client = mock.MagicMock()
        amplify_client.apps = {app.arn: app}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Scanner failure"),
            ),
        ):
            result = _execute_check(amplify_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            "Could not scan Amplify app test-app environment variables for secrets: Scanner failure"
            in result[0].status_extended
        )


def _build_app(environment_variables: dict, build_spec: str, branches: list) -> App:
    app_id = "app-12345"
    app_name = "test-app"
    app_arn = (
        f"arn:aws:amplify:{AWS_REGION_US_EAST_1}:" f"{AWS_ACCOUNT_NUMBER}:apps/{app_id}"
    )
    return App(
        id=app_id,
        name=app_name,
        arn=app_arn,
        region=AWS_REGION_US_EAST_1,
        environment_variables=environment_variables,
        build_spec=build_spec,
        branches=branches,
        tags=[],
    )


def _execute_check(amplify_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
            amplify_client,
        ),
    ):
        from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
            amplify_app_no_secrets_in_environment,
        )

        check = amplify_app_no_secrets_in_environment()
        return check.execute()
