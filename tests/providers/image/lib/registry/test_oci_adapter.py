from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryAuthError,
    ImageRegistryCatalogError,
    ImageRegistryNetworkError,
)
from prowler.providers.image.lib.registry.oci_adapter import OciRegistryAdapter


class TestOciAdapterInit:
    def test_normalise_url_adds_https(self):
        adapter = OciRegistryAdapter("myregistry.io")
        assert adapter._base_url == "https://myregistry.io"

    def test_normalise_url_keeps_http(self):
        adapter = OciRegistryAdapter("http://myregistry.io")
        assert adapter._base_url == "http://myregistry.io"

    def test_normalise_url_strips_trailing_slash(self):
        adapter = OciRegistryAdapter("https://myregistry.io/")
        assert adapter._base_url == "https://myregistry.io"

    def test_stores_credentials(self):
        adapter = OciRegistryAdapter("reg.io", username="u", password="p", token="t", verify_ssl=False)
        assert adapter.username == "u"
        assert adapter.password == "p"
        assert adapter.token == "t"
        assert adapter.verify_ssl is False


class TestOciAdapterAuth:
    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_ensure_auth_with_token(self, mock_request):
        adapter = OciRegistryAdapter("reg.io", token="my-token")
        adapter._ensure_auth()
        assert adapter._bearer_token == "my-token"
        mock_request.assert_not_called()

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_ensure_auth_anonymous_ok(self, mock_request):
        resp = MagicMock(status_code=200)
        mock_request.return_value = resp
        adapter = OciRegistryAdapter("reg.io")
        adapter._ensure_auth()
        assert adapter._bearer_token is None

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_ensure_auth_bearer_challenge(self, mock_request):
        ping_resp = MagicMock(status_code=401, headers={"Www-Authenticate": 'Bearer realm="https://auth.example.com/token",service="registry"'})
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "bearer-tok"}
        mock_request.side_effect = [ping_resp, token_resp]
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        adapter._ensure_auth()
        assert adapter._bearer_token == "bearer-tok"

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_ensure_auth_403_raises(self, mock_request):
        resp = MagicMock(status_code=403)
        mock_request.return_value = resp
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryAuthError):
            adapter._ensure_auth()


class TestOciAdapterListRepositories:
    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_list_repos_single_page(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        catalog_resp = MagicMock(status_code=200, headers={})
        catalog_resp.json.return_value = {"repositories": ["app/frontend", "app/backend"]}
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("reg.io")
        repos = adapter.list_repositories()
        assert repos == ["app/frontend", "app/backend"]

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_list_repos_paginated(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        page1_resp = MagicMock(status_code=200, headers={"Link": '<https://reg.io/v2/_catalog?n=200&last=b>; rel="next"'})
        page1_resp.json.return_value = {"repositories": ["a"]}
        page2_resp = MagicMock(status_code=200, headers={})
        page2_resp.json.return_value = {"repositories": ["b"]}
        mock_request.side_effect = [ping_resp, page1_resp, page2_resp]
        adapter = OciRegistryAdapter("reg.io")
        repos = adapter.list_repositories()
        assert repos == ["a", "b"]

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_list_repos_404_raises(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        catalog_resp = MagicMock(status_code=404)
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryCatalogError):
            adapter.list_repositories()


class TestOciAdapterListTags:
    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_list_tags(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        tags_resp = MagicMock(status_code=200, headers={})
        tags_resp.json.return_value = {"tags": ["latest", "v1.0"]}
        mock_request.side_effect = [ping_resp, tags_resp]
        adapter = OciRegistryAdapter("reg.io")
        tags = adapter.list_tags("myapp")
        assert tags == ["latest", "v1.0"]

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_list_tags_null_tags(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        tags_resp = MagicMock(status_code=200, headers={})
        tags_resp.json.return_value = {"tags": None}
        mock_request.side_effect = [ping_resp, tags_resp]
        adapter = OciRegistryAdapter("reg.io")
        tags = adapter.list_tags("myapp")
        assert tags == []


class TestOciAdapterRetry:
    @patch("prowler.providers.image.lib.registry.oci_adapter.time.sleep")
    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_retry_on_429(self, mock_request, mock_sleep):
        resp_429 = MagicMock(status_code=429)
        resp_200 = MagicMock(status_code=200)
        mock_request.side_effect = [resp_429, resp_200]
        adapter = OciRegistryAdapter("reg.io")
        result = adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert result.status_code == 200
        mock_sleep.assert_called_once()

    @patch("prowler.providers.image.lib.registry.oci_adapter.time.sleep")
    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_connection_error_retries(self, mock_request, mock_sleep):
        mock_request.side_effect = requests.exceptions.ConnectionError("failed")
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryNetworkError):
            adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert mock_request.call_count == 3

    @patch("prowler.providers.image.lib.registry.oci_adapter.requests.request")
    def test_timeout_raises_immediately(self, mock_request):
        mock_request.side_effect = requests.exceptions.Timeout("timeout")
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryNetworkError):
            adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert mock_request.call_count == 1


class TestOciAdapterNextPageUrl:
    def test_no_link_header(self):
        resp = MagicMock(headers={})
        assert OciRegistryAdapter._next_page_url(resp) is None

    def test_link_header_with_next(self):
        resp = MagicMock(headers={"Link": '<https://reg.io/v2/_catalog?n=200&last=b>; rel="next"'})
        assert OciRegistryAdapter._next_page_url(resp) == "https://reg.io/v2/_catalog?n=200&last=b"

    def test_link_header_no_next(self):
        resp = MagicMock(headers={"Link": '<https://reg.io/v2/_catalog?n=200>; rel="prev"'})
        assert OciRegistryAdapter._next_page_url(resp) is None
