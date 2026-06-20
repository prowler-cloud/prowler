from unittest.mock import MagicMock

from prowler.providers.e2e.lib.arguments.arguments import validate_arguments


class TestE2eArguments:
    def test_validate_arguments_success(self):
        arguments = MagicMock()
        arguments.e2e_api_key = "key"
        arguments.e2e_auth_token = "token"
        arguments.e2e_project_id = "123"

        valid, message = validate_arguments(arguments)

        assert valid is True
        assert message == ""

    def test_validate_arguments_missing_project_id(self):
        arguments = MagicMock()
        arguments.e2e_api_key = "key"
        arguments.e2e_auth_token = "token"
        arguments.e2e_project_id = None

        valid, message = validate_arguments(arguments)

        assert valid is False
        assert "project ID" in message

    def test_validate_arguments_invalid_project_id(self):
        arguments = MagicMock()
        arguments.e2e_api_key = "key"
        arguments.e2e_auth_token = "token"
        arguments.e2e_project_id = "abc"

        valid, message = validate_arguments(arguments)

        assert valid is False
        assert "integer" in message
