from unittest.mock import MagicMock

from prowler.providers.e2enetworks.lib.arguments.arguments import validate_arguments


class TestE2eArguments:
    def test_validate_arguments_success(self):
        arguments = MagicMock()
        arguments.e2e_networks_api_key = "key"
        arguments.e2e_networks_auth_token = "token"
        arguments.e2e_networks_project_id = "123"

        valid, message = validate_arguments(arguments)

        assert valid is True
        assert message == ""

    def test_validate_arguments_missing_credentials_allowed(self, monkeypatch):
        # Listing operations must work without credentials; presence is enforced
        # later at provider initialization, not here.
        monkeypatch.delenv("E2E_NETWORKS_API_KEY", raising=False)
        monkeypatch.delenv("E2E_NETWORKS_AUTH_TOKEN", raising=False)
        monkeypatch.delenv("E2E_NETWORKS_PROJECT_ID", raising=False)

        arguments = MagicMock()
        arguments.e2e_networks_api_key = None
        arguments.e2e_networks_auth_token = None
        arguments.e2e_networks_project_id = None

        valid, message = validate_arguments(arguments)

        assert valid is True
        assert message == ""

    def test_validate_arguments_invalid_project_id(self):
        arguments = MagicMock()
        arguments.e2e_networks_api_key = "key"
        arguments.e2e_networks_auth_token = "token"
        arguments.e2e_networks_project_id = "abc"

        valid, message = validate_arguments(arguments)

        assert valid is False
        assert "integer" in message
