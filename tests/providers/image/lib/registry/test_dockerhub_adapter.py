from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryAuthError,
    ImageRegistryCatalogError,
    ImageRegistryNetworkError,
)
from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter


class TestDockerHubAdapterInit:
    def test_extract_namespace_simple(self):
        assert DockerHubAdapter._extract_namespace("docker.io/myorg") == "myorg"

    def test_extract_namespace_https(self):
        assert DockerHubAdapter._extract_namespace("https://docker.io/myorg") == "myorg"

    def test_extract_namespace_registry1(self):
        assert (
            DockerHubAdapter._extract_namespace("registry-1.docker.io/myorg") == "myorg"
        )

    def test_extract_namespace_empty(self):
        assert DockerHubAdapter._extract_namespace("docker.io") == ""

    def test_extract_namespace_with_slash(self):
        assert DockerHubAdapter._extract_namespace("docker.io/myorg/") == "myorg"


class TestDockerHubListRepositories:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_repos(self, mock_request):
        # Hub login (now goes through requests.request via _request_with_retry)
        login_resp = MagicMock(status_code=200)
        login_resp.json.return_value = {"token": "jwt"}
        # Repo listing
        repos_resp = MagicMock(status_code=200)
        repos_resp.json.return_value = {
            "results": [{"name": "app1"}, {"name": "app2"}],
            "next": None,
        }
        mock_request.side_effect = [login_resp, repos_resp]
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        repos = adapter.list_repositories()
        assert repos == ["myorg/app1", "myorg/app2"]

    def test_list_repos_no_namespace_raises(self):
        adapter = DockerHubAdapter("docker.io")
        with pytest.raises(ImageRegistryCatalogError, match="namespace"):
            adapter.list_repositories()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_repos_public_no_credentials(self, mock_request):
        """When no credentials are provided, use the public /v2/repositories/{ns}/ endpoint."""
        repos_resp = MagicMock(status_code=200)
        repos_resp.json.return_value = {
            "results": [{"name": "repo1"}, {"name": "repo2"}],
            "next": None,
        }
        mock_request.return_value = repos_resp
        adapter = DockerHubAdapter("docker.io/publicns")
        repos = adapter.list_repositories()
        assert repos == ["publicns/repo1", "publicns/repo2"]
        called_url = mock_request.call_args[0][1]
        assert "/v2/repositories/publicns/" in called_url
        assert "/v2/namespaces/" not in called_url


class TestDockerHubListTags:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_tags(self, mock_request):
        # Token exchange (now goes through requests.request via _request_with_retry)
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "registry-token"}
        # Tag listing
        tags_resp = MagicMock(status_code=200, headers={})
        tags_resp.json.return_value = {"tags": ["latest", "v1.0"]}
        mock_request.side_effect = [token_resp, tags_resp]
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        tags = adapter.list_tags("myorg/myapp")
        assert tags == ["latest", "v1.0"]

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_tags_auth_failure(self, mock_request):
        # Token exchange
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "tok"}
        # Tag listing returns 401
        tags_resp = MagicMock(status_code=401)
        mock_request.side_effect = [token_resp, tags_resp]
        adapter = DockerHubAdapter("docker.io/myorg")
        with pytest.raises(ImageRegistryAuthError):
            adapter.list_tags("myorg/myapp")


class TestDockerHubLogin:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_login_failure(self, mock_request):
        resp = MagicMock(status_code=401, text="invalid credentials")
        mock_request.return_value = resp
        adapter = DockerHubAdapter("docker.io/myorg", username="bad", password="creds")
        with pytest.raises(ImageRegistryAuthError, match="login failed"):
            adapter._hub_login()

    def test_login_skipped_without_credentials(self):
        adapter = DockerHubAdapter("docker.io/myorg")
        adapter._hub_login()  # Should not raise
        assert adapter._hub_jwt is None

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_login_401_includes_response_body(self, mock_request):
        resp = MagicMock(
            status_code=401, text='{"detail":"Incorrect authentication credentials"}'
        )
        mock_request.return_value = resp
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        with pytest.raises(
            ImageRegistryAuthError, match="Incorrect authentication credentials"
        ):
            adapter._hub_login()

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_login_500_retried_then_raises_network_error(
        self, mock_request, mock_sleep
    ):
        mock_request.return_value = MagicMock(status_code=500)
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        with pytest.raises(ImageRegistryNetworkError, match="Server error"):
            adapter._hub_login()
        assert mock_request.call_count == 3


class TestDockerHubRetry:
    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_retry_on_429(self, mock_request, mock_sleep):
        resp_429 = MagicMock(status_code=429)
        resp_200 = MagicMock(status_code=200)
        mock_request.side_effect = [resp_429, resp_200]
        adapter = DockerHubAdapter("docker.io/myorg")
        result = adapter._request_with_retry(
            "GET", "https://hub.docker.com/v2/namespaces/myorg/repositories"
        )
        assert result.status_code == 200

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_connection_error_retries(self, mock_request, mock_sleep):
        mock_request.side_effect = requests.exceptions.ConnectionError("fail")
        adapter = DockerHubAdapter("docker.io/myorg")
        with pytest.raises(ImageRegistryNetworkError):
            adapter._request_with_retry("GET", "https://hub.docker.com")
        assert mock_request.call_count == 3

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_retry_on_500(self, mock_request, mock_sleep):
        resp_500 = MagicMock(status_code=500)
        resp_200 = MagicMock(status_code=200)
        mock_request.side_effect = [resp_500, resp_200]
        adapter = DockerHubAdapter("docker.io/myorg")
        result = adapter._request_with_retry("GET", "https://hub.docker.com")
        assert result.status_code == 200
        assert mock_request.call_count == 2
        mock_sleep.assert_called_once()

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_retry_exhausted_on_500_raises_network_error(
        self, mock_request, mock_sleep
    ):
        mock_request.return_value = MagicMock(status_code=500)
        adapter = DockerHubAdapter("docker.io/myorg")
        with pytest.raises(
            ImageRegistryNetworkError, match="Server error.*HTTP 500.*3 attempts"
        ):
            adapter._request_with_retry("GET", "https://hub.docker.com")
        assert mock_request.call_count == 3

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_4xx_not_retried(self, mock_request, mock_sleep):
        mock_request.return_value = MagicMock(status_code=403)
        adapter = DockerHubAdapter("docker.io/myorg")
        result = adapter._request_with_retry("GET", "https://hub.docker.com")
        assert result.status_code == 403
        assert mock_request.call_count == 1
        mock_sleep.assert_not_called()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_request_sends_user_agent(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)
        adapter = DockerHubAdapter("docker.io/myorg")
        adapter._request_with_retry("GET", "https://hub.docker.com")
        _, kwargs = mock_request.call_args
        from prowler.config.config import prowler_version

        assert (
            kwargs["headers"]["User-Agent"]
            == f"Prowler/{prowler_version} (registry-adapter)"
        )

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_retry_500_includes_response_body(self, mock_request, mock_sleep):
        resp_500 = MagicMock(status_code=500, text="<html>Cloudflare error</html>")
        mock_request.return_value = resp_500
        adapter = DockerHubAdapter("docker.io/myorg")
        with pytest.raises(ImageRegistryNetworkError, match="Cloudflare error"):
            adapter._request_with_retry("GET", "https://hub.docker.com")


class TestDockerHubEmptyTokens:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_empty_hub_jwt_raises(self, mock_request):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"token": ""}
        mock_request.return_value = resp
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        with pytest.raises(ImageRegistryAuthError, match="empty JWT"):
            adapter._hub_login()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_none_hub_jwt_raises(self, mock_request):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {}
        mock_request.return_value = resp
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        with pytest.raises(ImageRegistryAuthError, match="empty JWT"):
            adapter._hub_login()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_empty_registry_token_raises(self, mock_request):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"token": ""}
        mock_request.return_value = resp
        adapter = DockerHubAdapter("docker.io/myorg", username="u", password="p")
        with pytest.raises(ImageRegistryAuthError, match="empty token"):
            adapter._get_registry_token("myorg/myapp")
