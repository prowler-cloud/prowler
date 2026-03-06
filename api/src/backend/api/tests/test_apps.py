import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings

import api
import api.apps as api_apps_module
from api.apps import (
    ApiConfig,
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
    SIGNING_KEY_ENV,
    VERIFYING_KEY_ENV,
)


@pytest.fixture(autouse=True)
def reset_keys_initialized(monkeypatch):
    """Ensure per-test clean state for the module-level guard flag."""
    monkeypatch.setattr(api_apps_module, "_keys_initialized", False, raising=False)


def _stub_keys():
    return (
        """-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n""",
        """-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n""",
    )


def test_generate_jwt_keys_when_missing(monkeypatch, tmp_path):
    # Arrange: isolate FS, env, and settings; force generation path
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(VERIFYING_KEY_ENV, raising=False)

    # Work on a copy of SIMPLE_JWT to avoid mutating the global settings dict for other tests
    monkeypatch.setattr(
        settings, "SIMPLE_JWT", settings.SIMPLE_JWT.copy(), raising=False
    )
    monkeypatch.setattr(settings, "TESTING", False, raising=False)

    # Avoid dependency on the cryptography package
    monkeypatch.setattr(ApiConfig, "_generate_jwt_keys", staticmethod(_stub_keys))

    config = ApiConfig("api", api_apps_module)

    # Act
    config._ensure_crypto_keys()

    # Assert: files created with expected content
    priv_path = Path(tmp_path) / PRIVATE_KEY_FILE
    pub_path = Path(tmp_path) / PUBLIC_KEY_FILE
    assert priv_path.is_file()
    assert pub_path.is_file()
    assert priv_path.read_text() == _stub_keys()[0]
    assert pub_path.read_text() == _stub_keys()[1]

    # Env vars and Django settings updated
    assert os.environ[SIGNING_KEY_ENV] == _stub_keys()[0]
    assert os.environ[VERIFYING_KEY_ENV] == _stub_keys()[1]
    assert settings.SIMPLE_JWT["SIGNING_KEY"] == _stub_keys()[0]
    assert settings.SIMPLE_JWT["VERIFYING_KEY"] == _stub_keys()[1]


def test_ensure_crypto_keys_are_idempotent_within_process(monkeypatch, tmp_path):
    # Arrange
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    monkeypatch.delenv(VERIFYING_KEY_ENV, raising=False)
    monkeypatch.setattr(
        settings, "SIMPLE_JWT", settings.SIMPLE_JWT.copy(), raising=False
    )
    monkeypatch.setattr(settings, "TESTING", False, raising=False)

    mock_generate = MagicMock(side_effect=_stub_keys)
    monkeypatch.setattr(ApiConfig, "_generate_jwt_keys", staticmethod(mock_generate))

    config = ApiConfig("api", api_apps_module)

    # Act: first call should generate, second should be a no-op (guard flag)
    config._ensure_crypto_keys()
    config._ensure_crypto_keys()

    # Assert: generation occurred exactly once
    assert mock_generate.call_count == 1


def test_ensure_jwt_keys_uses_existing_files(monkeypatch, tmp_path):
    # Arrange: pre-create key files
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.setattr(
        settings, "SIMPLE_JWT", settings.SIMPLE_JWT.copy(), raising=False
    )

    existing_private, existing_public = _stub_keys()

    (Path(tmp_path) / PRIVATE_KEY_FILE).write_text(existing_private)
    (Path(tmp_path) / PUBLIC_KEY_FILE).write_text(existing_public)

    # If generation were called, fail the test
    def _fail_generate():
        raise AssertionError("_generate_jwt_keys should not be called when files exist")

    monkeypatch.setattr(ApiConfig, "_generate_jwt_keys", staticmethod(_fail_generate))

    config = ApiConfig("api", api_apps_module)

    # Act: call the lower-level method directly to set env/settings from files
    config._ensure_jwt_keys()

    # Assert
    # _read_key_file() strips trailing newlines; environment/settings should reflect stripped content
    assert os.environ[SIGNING_KEY_ENV] == existing_private.strip()
    assert os.environ[VERIFYING_KEY_ENV] == existing_public.strip()
    assert settings.SIMPLE_JWT["SIGNING_KEY"] == existing_private.strip()
    assert settings.SIMPLE_JWT["VERIFYING_KEY"] == existing_public.strip()


def test_ensure_crypto_keys_skips_when_env_vars(monkeypatch, tmp_path):
    # Arrange: put values in env so the orchestrator doesn't generate
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.setenv(SIGNING_KEY_ENV, "ENV-PRIVATE")
    monkeypatch.setenv(VERIFYING_KEY_ENV, "ENV-PUBLIC")
    monkeypatch.setattr(
        settings, "SIMPLE_JWT", settings.SIMPLE_JWT.copy(), raising=False
    )
    monkeypatch.setattr(settings, "TESTING", False, raising=False)

    called = {"ensure": False}

    def _track_call():
        called["ensure"] = True
        return _stub_keys()

    monkeypatch.setattr(ApiConfig, "_generate_jwt_keys", staticmethod(_track_call))

    config = ApiConfig("api", api_apps_module)

    # Act
    config._ensure_crypto_keys()

    # Assert: orchestrator did not trigger generation when env present
    assert called["ensure"] is False


@pytest.fixture(autouse=True)
def stub_api_modules():
    """Provide dummy modules imported during ApiConfig.ready()."""
    created = []
    for name in ("api.schema_extensions", "api.signals"):
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)
            created.append(name)

    yield

    for name in created:
        sys.modules.pop(name, None)


def _set_argv(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", argv, raising=False)


def _set_testing(monkeypatch, value):
    monkeypatch.setattr(settings, "TESTING", value, raising=False)


def _make_app():
    return ApiConfig("api", api)


def test_ready_initializes_driver_for_api_process(monkeypatch):
    config = _make_app()
    _set_argv(monkeypatch, ["gunicorn"])
    _set_testing(monkeypatch, False)

    with patch.object(ApiConfig, "_ensure_crypto_keys", return_value=None), patch(
        "api.attack_paths.database.init_driver"
    ) as init_driver:
        config.ready()

    init_driver.assert_called_once()


def test_ready_skips_driver_for_celery(monkeypatch):
    config = _make_app()
    _set_argv(monkeypatch, ["celery", "-A", "api"])
    _set_testing(monkeypatch, False)

    with patch.object(ApiConfig, "_ensure_crypto_keys", return_value=None), patch(
        "api.attack_paths.database.init_driver"
    ) as init_driver:
        config.ready()

    init_driver.assert_not_called()


def test_ready_skips_driver_for_manage_py_skip_command(monkeypatch):
    config = _make_app()
    _set_argv(monkeypatch, ["manage.py", "migrate"])
    _set_testing(monkeypatch, False)

    with patch.object(ApiConfig, "_ensure_crypto_keys", return_value=None), patch(
        "api.attack_paths.database.init_driver"
    ) as init_driver:
        config.ready()

    init_driver.assert_not_called()


def test_ready_skips_driver_when_testing(monkeypatch):
    config = _make_app()
    _set_argv(monkeypatch, ["gunicorn"])
    _set_testing(monkeypatch, True)

    with patch.object(ApiConfig, "_ensure_crypto_keys", return_value=None), patch(
        "api.attack_paths.database.init_driver"
    ) as init_driver:
        config.ready()

    init_driver.assert_not_called()
