"""Tests for StackIT Provider input validation."""

import sys
import types
from argparse import Namespace
from unittest.mock import patch

import pytest

import prowler.providers.common.provider as common_provider
from prowler.providers.common.models import Connection
from prowler.providers.stackit.exceptions.exceptions import (
    StackITAPIError,
    StackITInvalidProjectIdError,
    StackITInvalidTokenError,
    StackITNonExistentTokenError,
)
from prowler.providers.stackit.stackit_provider import StackitProvider


class TestStackITProviderValidation:
    """Test suite for StackIT Provider input validation."""

    KEY_PATH = "/tmp/sa-key.json"
    VALID_PROJECT_ID = "12345678-1234-1234-1234-123456789abc"

    def test_validate_arguments_valid(self):
        """Test validation passes with a key path and a valid UUID."""
        StackitProvider.validate_arguments(self.VALID_PROJECT_ID, self.KEY_PATH)

    def test_validate_arguments_empty_key_path(self):
        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments(self.VALID_PROJECT_ID, "")
        assert "service account credentials are required" in str(exc_info.value)

    def test_validate_arguments_none_key_path(self):
        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments(self.VALID_PROJECT_ID, None)
        assert "service account credentials are required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_key_path(self):
        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments(self.VALID_PROJECT_ID, "   ")
        assert "service account credentials are required" in str(exc_info.value)

    def test_validate_arguments_empty_project_id(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments("", self.KEY_PATH)
        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_none_project_id(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(None, self.KEY_PATH)
        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_project_id(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments("   ", self.KEY_PATH)
        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_format(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments("not-a-valid-uuid", self.KEY_PATH)
        assert "must be a valid UUID format" in str(exc_info.value)
        assert "not-a-valid-uuid" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_too_short(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments("1234-5678", self.KEY_PATH)
        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_without_hyphens(self):
        """Python's UUID() accepts compact form."""
        StackitProvider.validate_arguments(
            "12345678123412341234123456789abc", self.KEY_PATH
        )

    def test_validate_arguments_numeric_only_project_id(self):
        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments("123456789012", self.KEY_PATH)
        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_with_uppercase(self):
        StackitProvider.validate_arguments(
            "12345678-1234-1234-1234-123456789ABC", self.KEY_PATH
        )

    def test_validate_arguments_uuid_with_braces(self):
        StackitProvider.validate_arguments(
            "{12345678-1234-1234-1234-123456789abc}", self.KEY_PATH
        )

    def test_validate_arguments_uuid_v4_format(self):
        StackitProvider.validate_arguments(
            "550e8400-e29b-41d4-a716-446655440000", self.KEY_PATH
        )

    def test_validate_arguments_both_invalid(self):
        """Key path is checked first."""
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments("not-a-uuid", "")

    def test_validate_arguments_both_none(self):
        """Key path is checked first."""
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments(None, None)

    def test_validate_arguments_accepts_inline_key_without_path(self):
        """Inline key content alone is enough; the path can be omitted."""
        StackitProvider.validate_arguments(
            self.VALID_PROJECT_ID, None, '{"keyId": "abc"}'
        )

    def test_validate_arguments_accepts_inline_key_when_path_is_empty(self):
        StackitProvider.validate_arguments(
            self.VALID_PROJECT_ID, "", '{"keyId": "abc"}'
        )

    def test_validate_arguments_rejects_when_inline_key_is_whitespace(self):
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments(self.VALID_PROJECT_ID, None, "   ")


class TestStackITProviderInitialization:
    def test_init_global_provider_passes_key_path_from_cli(self, monkeypatch):
        """The service account key path and inline key content from CLI args
        are forwarded to the provider constructor; tokens are not part of
        the API anymore."""
        captured_kwargs = {}

        class FakeStackitProvider:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)

        fake_module = types.SimpleNamespace(StackitProvider=FakeStackitProvider)
        arguments = Namespace(
            provider="stackit",
            stackit_project_id="12345678-1234-1234-1234-123456789abc",
            stackit_service_account_key_path="/tmp/sa-key.json",
            stackit_service_account_key='{"keyId": "abc"}',
            stackit_region=None,
            scan_unused_services=False,
            config_file="config.yaml",
            mutelist_file=None,
            fixer_config="fixer_config.yaml",
        )

        monkeypatch.setattr(common_provider.Provider, "_global", None)

        with (
            patch.object(common_provider, "import_module", return_value=fake_module),
            patch.object(
                common_provider, "load_and_validate_config_file", return_value={}
            ),
        ):
            common_provider.Provider.init_global_provider(arguments)

        assert "api_token" not in captured_kwargs
        assert captured_kwargs["project_id"] == arguments.stackit_project_id
        assert (
            captured_kwargs["service_account_key_path"]
            == arguments.stackit_service_account_key_path
        )
        assert (
            captured_kwargs["service_account_key"]
            == arguments.stackit_service_account_key
        )
        assert captured_kwargs["scan_unused_services"] is False

    def test_init_global_provider_passes_scan_unused_services_true(self, monkeypatch):
        """scan_unused_services=True is forwarded to the provider constructor."""
        captured_kwargs = {}

        class FakeStackitProvider:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)

        fake_module = types.SimpleNamespace(StackitProvider=FakeStackitProvider)
        arguments = Namespace(
            provider="stackit",
            stackit_project_id="12345678-1234-1234-1234-123456789abc",
            stackit_service_account_key_path="/tmp/sa-key.json",
            stackit_region=None,
            scan_unused_services=True,
            config_file="config.yaml",
            mutelist_file=None,
            fixer_config="fixer_config.yaml",
        )

        monkeypatch.setattr(common_provider.Provider, "_global", None)

        with (
            patch.object(common_provider, "import_module", return_value=fake_module),
            patch.object(
                common_provider, "load_and_validate_config_file", return_value={}
            ),
        ):
            common_provider.Provider.init_global_provider(arguments)

        assert captured_kwargs["scan_unused_services"] is True


class TestStackITProviderTestConnection:
    KEY_PATH = "/tmp/sa-key.json"
    KEY_CONTENT = '{"keyId": "abc", "publicKey": "..."}'
    PROJECT_ID = "12345678-1234-1234-1234-123456789abc"

    @pytest.fixture
    def fake_stackit_resourcemanager(self, monkeypatch):
        configuration_module = types.ModuleType("stackit.core.configuration")
        resourcemanager_module = types.ModuleType("stackit.resourcemanager")

        class FakeConfiguration:
            def __init__(self, service_account_key_path=None, service_account_key=None):
                self.service_account_key_path = service_account_key_path
                self.service_account_key = service_account_key

        class FakeDefaultApi:
            error = None
            calls = []

            def __init__(self, config):
                self.config = config

            def get_project(self, id):
                self.__class__.calls.append(
                    (
                        self.config.service_account_key_path,
                        self.config.service_account_key,
                        id,
                    )
                )
                if self.__class__.error:
                    raise self.__class__.error
                return {"name": "Test Project"}

        configuration_module.Configuration = FakeConfiguration
        resourcemanager_module.DefaultApi = FakeDefaultApi

        monkeypatch.setitem(
            sys.modules, "stackit.core.configuration", configuration_module
        )
        monkeypatch.setitem(
            sys.modules, "stackit.resourcemanager", resourcemanager_module
        )
        return FakeDefaultApi

    def test_connection_success_with_key_path(self, fake_stackit_resourcemanager):
        connection = StackitProvider.test_connection(
            project_id=self.PROJECT_ID,
            service_account_key_path=self.KEY_PATH,
        )

        assert connection == Connection(is_connected=True)
        assert fake_stackit_resourcemanager.calls == [
            (self.KEY_PATH, None, self.PROJECT_ID)
        ]

    def test_connection_success_with_inline_key(self, fake_stackit_resourcemanager):
        """The inline key path takes precedence over the file path."""
        connection = StackitProvider.test_connection(
            project_id=self.PROJECT_ID,
            service_account_key=self.KEY_CONTENT,
        )

        assert connection == Connection(is_connected=True)
        assert fake_stackit_resourcemanager.calls == [
            (None, self.KEY_CONTENT, self.PROJECT_ID)
        ]

    def test_connection_inline_key_overrides_path(self, fake_stackit_resourcemanager):
        connection = StackitProvider.test_connection(
            project_id=self.PROJECT_ID,
            service_account_key_path=self.KEY_PATH,
            service_account_key=self.KEY_CONTENT,
        )

        assert connection == Connection(is_connected=True)
        # When the inline key is present the SDK is configured with it and
        # the key path is not passed on at all.
        assert fake_stackit_resourcemanager.calls == [
            (None, self.KEY_CONTENT, self.PROJECT_ID)
        ]

    def test_connection_returns_error_when_raise_on_exception_is_false(
        self, fake_stackit_resourcemanager
    ):
        fake_stackit_resourcemanager.error = RuntimeError("denied")

        connection = StackitProvider.test_connection(
            project_id=self.PROJECT_ID,
            service_account_key_path=self.KEY_PATH,
            raise_on_exception=False,
        )

        assert isinstance(connection.error, StackITAPIError)
        assert "Failed to connect to StackIT using Resource Manager" in str(
            connection.error
        )

    def test_connection_raises_when_raise_on_exception_is_true(
        self, fake_stackit_resourcemanager
    ):
        fake_stackit_resourcemanager.error = RuntimeError("denied")

        with pytest.raises(StackITAPIError):
            StackitProvider.test_connection(
                project_id=self.PROJECT_ID,
                service_account_key_path=self.KEY_PATH,
                raise_on_exception=True,
            )


class TestStackITProviderGetProjectName:
    @pytest.fixture
    def fake_resourcemanager(self, monkeypatch):
        configuration_module = types.ModuleType("stackit.core.configuration")
        resourcemanager_module = types.ModuleType("stackit.resourcemanager")

        class FakeConfiguration:
            def __init__(self, service_account_key_path):
                self.service_account_key_path = service_account_key_path

        class FakeDefaultApi:
            error = None

            def __init__(self, config):
                pass

            def get_project(self, id):
                if self.__class__.error:
                    raise self.__class__.error
                return {"name": "My Project"}

        configuration_module.Configuration = FakeConfiguration
        resourcemanager_module.DefaultApi = FakeDefaultApi

        monkeypatch.setitem(
            sys.modules, "stackit.core.configuration", configuration_module
        )
        monkeypatch.setitem(
            sys.modules, "stackit.resourcemanager", resourcemanager_module
        )
        return FakeDefaultApi

    def _make_provider(self):
        provider = object.__new__(StackitProvider)
        provider._service_account_key_path = "/tmp/sa-key.json"
        provider._service_account_key = None
        provider._project_id = "12345678-1234-1234-1234-123456789abc"
        return provider

    def test_get_project_name_403_raises_invalid_token_error(
        self, fake_resourcemanager
    ):
        class Http403Error(Exception):
            status = 403

        fake_resourcemanager.error = Http403Error()
        provider = self._make_provider()

        with pytest.raises(StackITInvalidTokenError):
            provider._get_project_name()

    def test_get_project_name_401_raises_invalid_token_error(
        self, fake_resourcemanager
    ):
        class Http401Error(Exception):
            status = 401

        fake_resourcemanager.error = Http401Error()
        provider = self._make_provider()

        with pytest.raises(StackITInvalidTokenError):
            provider._get_project_name()

    def test_get_project_name_other_error_returns_empty_string(
        self, fake_resourcemanager
    ):
        fake_resourcemanager.error = RuntimeError("network error")
        provider = self._make_provider()

        result = provider._get_project_name()

        assert result == ""


class Test_StackitProvider_Handle_API_Error:
    """Direct coverage for ``StackitProvider.handle_api_error`` so 401 and 403
    are treated as credential failures by every service call site, not just
    ``_get_project_name``.
    """

    def _http(self, status_code: int) -> Exception:
        err = Exception(f"http {status_code}")
        err.status = status_code
        return err

    def test_401_raises_invalid_token_error(self):
        with pytest.raises(StackITInvalidTokenError):
            StackitProvider.handle_api_error(self._http(401))

    def test_403_raises_invalid_token_error(self):
        with pytest.raises(StackITInvalidTokenError):
            StackitProvider.handle_api_error(self._http(403))

    def test_other_http_status_is_reraised_unchanged(self):
        original = self._http(500)
        with pytest.raises(Exception) as excinfo:
            StackitProvider.handle_api_error(original)
        assert excinfo.value is original

    def test_exception_without_status_is_reraised_unchanged(self):
        original = RuntimeError("network error")
        with pytest.raises(RuntimeError) as excinfo:
            StackitProvider.handle_api_error(original)
        assert excinfo.value is original
