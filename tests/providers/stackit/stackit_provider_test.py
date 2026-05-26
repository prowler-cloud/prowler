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

    def test_validate_arguments_valid_uuid(self):
        """Test validation passes with valid UUID and token."""
        valid_token = "test-api-token-12345"
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_empty_token(self):
        """Test validation fails with empty API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments("", valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_none_token(self):
        """Test validation fails with None API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments(None, valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_token(self):
        """Test validation fails with whitespace-only API token."""
        valid_project_id = "12345678-1234-1234-1234-123456789abc"

        with pytest.raises(StackITNonExistentTokenError) as exc_info:
            StackitProvider.validate_arguments("   ", valid_project_id)

        assert "API token is required" in str(exc_info.value)

    def test_validate_arguments_empty_project_id(self):
        """Test validation fails with empty project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, "")

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_none_project_id(self):
        """Test validation fails with None project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, None)

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_whitespace_only_project_id(self):
        """Test validation fails with whitespace-only project ID."""
        valid_token = "test-api-token-12345"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, "   ")

        assert "project ID is required" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_format(self):
        """Test validation fails with invalid UUID format for project ID."""
        valid_token = "test-api-token-12345"
        invalid_project_id = "not-a-valid-uuid"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)
        assert "not-a-valid-uuid" in str(exc_info.value)

    def test_validate_arguments_invalid_uuid_too_short(self):
        """Test validation fails with too short project ID."""
        valid_token = "test-api-token-12345"
        invalid_project_id = "1234-5678"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_without_hyphens(self):
        """Test validation passes with UUID without hyphens (Python's UUID() normalizes it)."""
        valid_token = "test-api-token-12345"
        # Missing hyphens - Python's UUID() accepts this and normalizes it
        valid_project_id = "12345678123412341234123456789abc"

        # Should not raise exception - Python's UUID() handles this
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_numeric_only_project_id(self):
        """Test validation fails with numeric-only project ID (not UUID)."""
        valid_token = "test-api-token-12345"
        # AWS-style numeric account ID (not valid UUID)
        invalid_project_id = "123456789012"

        with pytest.raises(StackITInvalidProjectIdError) as exc_info:
            StackitProvider.validate_arguments(valid_token, invalid_project_id)

        assert "must be a valid UUID format" in str(exc_info.value)

    def test_validate_arguments_uuid_with_uppercase(self):
        """Test validation passes with uppercase UUID (should be normalized)."""
        valid_token = "test-api-token-12345"
        # UUIDs are case-insensitive
        valid_project_id = "12345678-1234-1234-1234-123456789ABC"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_uuid_with_braces(self):
        """Test validation fails with UUID in braces (not standard format)."""
        valid_token = "test-api-token-12345"
        # Some systems use {UUID} format, but Python's UUID() should handle it
        valid_project_id = "{12345678-1234-1234-1234-123456789abc}"

        # Should not raise exception - Python's UUID() handles braces
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_uuid_v4_format(self):
        """Test validation passes with valid UUID v4 format."""
        valid_token = "test-api-token-12345"
        # Standard UUID v4 format
        valid_project_id = "550e8400-e29b-41d4-a716-446655440000"

        # Should not raise any exception
        StackitProvider.validate_arguments(valid_token, valid_project_id)

    def test_validate_arguments_both_invalid(self):
        """Test validation fails with both token and project_id invalid."""
        # Should fail on token first (checked first in the method)
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments("", "not-a-uuid")

    def test_validate_arguments_both_none(self):
        """Test validation fails with both token and project_id None."""
        # Should fail on token first (checked first in the method)
        with pytest.raises(StackITNonExistentTokenError):
            StackitProvider.validate_arguments(None, None)


class TestStackITProviderInitialization:
    def test_init_global_provider_uses_environment_token(self, monkeypatch):
        """StackIT API tokens are env-only and not read from CLI arguments."""
        captured_kwargs = {}

        class FakeStackitProvider:
            def __init__(self, **kwargs):
                captured_kwargs.update(kwargs)

        fake_module = types.SimpleNamespace(StackitProvider=FakeStackitProvider)
        arguments = Namespace(
            provider="stackit",
            stackit_project_id="12345678-1234-1234-1234-123456789abc",
            stackit_region=None,
            scan_unused_services=False,
            config_file="config.yaml",
            mutelist_file=None,
            fixer_config="fixer_config.yaml",
        )

        monkeypatch.setenv("STACKIT_API_TOKEN", "env-token")
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
            stackit_region=None,
            scan_unused_services=True,
            config_file="config.yaml",
            mutelist_file=None,
            fixer_config="fixer_config.yaml",
        )

        monkeypatch.setenv("STACKIT_API_TOKEN", "env-token")
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
    @pytest.fixture
    def fake_stackit_resourcemanager(self, monkeypatch):
        configuration_module = types.ModuleType("stackit.core.configuration")
        resourcemanager_module = types.ModuleType("stackit.resourcemanager")

        class FakeConfiguration:
            def __init__(self, service_account_token):
                self.service_account_token = service_account_token

        class FakeDefaultApi:
            error = None
            calls = []

            def __init__(self, config):
                self.config = config

            def get_project(self, id):
                self.__class__.calls.append((self.config.service_account_token, id))
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

    def test_connection_success_uses_resource_manager_lookup(
        self, fake_stackit_resourcemanager
    ):
        connection = StackitProvider.test_connection(
            api_token="token",
            project_id="12345678-1234-1234-1234-123456789abc",
        )

        assert connection == Connection(is_connected=True)
        assert fake_stackit_resourcemanager.calls == [
            ("token", "12345678-1234-1234-1234-123456789abc")
        ]

    def test_connection_returns_error_when_raise_on_exception_is_false(
        self, fake_stackit_resourcemanager
    ):
        fake_stackit_resourcemanager.error = RuntimeError("denied")

        connection = StackitProvider.test_connection(
            api_token="token",
            project_id="12345678-1234-1234-1234-123456789abc",
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
                api_token="token",
                project_id="12345678-1234-1234-1234-123456789abc",
                raise_on_exception=True,
            )


class TestStackITProviderGetProjectName:
    @pytest.fixture
    def fake_resourcemanager(self, monkeypatch):
        configuration_module = types.ModuleType("stackit.core.configuration")
        resourcemanager_module = types.ModuleType("stackit.resourcemanager")

        class FakeConfiguration:
            def __init__(self, service_account_token):
                self.service_account_token = service_account_token

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
        provider._api_token = "token"
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
