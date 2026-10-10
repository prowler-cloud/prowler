import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import api
import api.apps as api_apps_module
import pytest
from api.apps import (
    ENCRYPTION_KEY_ENV,
    ENCRYPTION_KEY_FILE,
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
    SECRET_KEY_ENV,
    SECRET_KEY_FILE,
    SIGNING_KEY_ENV,
    VERIFYING_KEY_ENV,
    ApiConfig,
)
from cryptography.fernet import Fernet
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


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


@pytest.mark.parametrize(
    "argv",
    [
        ["gunicorn"],
        ["celery", "-A", "api"],
        ["manage.py", "migrate"],
    ],
    ids=["api", "celery", "manage_py"],
)
def test_ready_never_eagerly_initializes_neo4j_driver(monkeypatch, argv):
    """ready() must never contact Neo4j; the driver is created lazily on first use."""
    config = _make_app()
    _set_argv(monkeypatch, argv)
    _set_testing(monkeypatch, False)

    with (
        patch.object(ApiConfig, "_ensure_crypto_keys", return_value=None),
        patch("api.attack_paths.database.init_driver") as init_driver,
    ):
        config.ready()

    init_driver.assert_not_called()


@pytest.fixture
def secrets_dir(monkeypatch, tmp_path):
    """Isolated key directory with both symmetric secrets empty and generation enabled."""
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.setattr(settings, "TESTING", False, raising=False)
    monkeypatch.setattr(settings, "SECRET_KEY", settings.SECRET_KEY, raising=False)
    monkeypatch.setattr(settings, "SECRETS_ENCRYPTION_KEY", "", raising=False)
    monkeypatch.setattr(
        settings, "DRF_API_KEY", settings.DRF_API_KEY.copy(), raising=False
    )
    monkeypatch.delenv(ENCRYPTION_KEY_ENV, raising=False)
    monkeypatch.delenv(SECRET_KEY_ENV, raising=False)
    return Path(tmp_path)


def _throwaway_fernet_key():
    return Fernet.generate_key().decode()


def test_ensure_secrets_refuses_published_encryption_key(monkeypatch, secrets_dir):
    published = _throwaway_fernet_key()
    monkeypatch.setattr(settings, "SECRETS_ENCRYPTION_KEY", published, raising=False)
    monkeypatch.setattr(
        api_apps_module,
        "PUBLISHED_ENCRYPTION_KEY_DIGESTS",
        frozenset({api_apps_module._digest(published)}),
        raising=False,
    )

    with pytest.raises(ImproperlyConfigured) as exc_info:
        _make_app()._ensure_secrets()

    assert ENCRYPTION_KEY_ENV in str(exc_info.value)
    assert published not in str(exc_info.value)
    assert not (secrets_dir / ENCRYPTION_KEY_FILE).exists()


def test_ensure_crypto_keys_refuses_published_signing_key(monkeypatch, tmp_path):
    published, verifying = _stub_keys()
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", Path(tmp_path), raising=False
    )
    monkeypatch.setattr(api_apps_module, "_keys_initialized", False, raising=False)
    monkeypatch.setenv(SIGNING_KEY_ENV, published)
    monkeypatch.setenv(VERIFYING_KEY_ENV, verifying)
    monkeypatch.setattr(settings, "TESTING", False, raising=False)
    monkeypatch.setattr(
        api_apps_module,
        "PUBLISHED_SIGNING_KEY_DIGESTS",
        frozenset({api_apps_module._pem_digest(published)}),
        raising=False,
    )

    with pytest.raises(ImproperlyConfigured) as exc_info:
        ApiConfig("api", api_apps_module)._ensure_crypto_keys()

    assert SIGNING_KEY_ENV in str(exc_info.value)
    assert "PRIVATE" not in str(exc_info.value)
    assert not (Path(tmp_path) / PRIVATE_KEY_FILE).exists()


def test_pem_digest_ignores_indentation_and_wrapping():
    # derived from the existing stub so no PEM literal is added to this file
    flat = _stub_keys()[0]
    indented = "".join(f"    {line}\n" for line in flat.splitlines())
    wrapped = flat.replace("PRIVATE\n", "PRIV\nATE\n", 1)

    assert api_apps_module._pem_digest(indented) == api_apps_module._pem_digest(flat)
    assert api_apps_module._pem_digest(wrapped) == api_apps_module._pem_digest(flat)


def test_ensure_secrets_generates_encryption_key_when_empty(secrets_dir):
    _make_app()._ensure_secrets()

    key_path = secrets_dir / ENCRYPTION_KEY_FILE
    generated = key_path.read_text()
    assert key_path.stat().st_mode & 0o777 == 0o600
    Fernet(generated.encode())
    assert settings.SECRETS_ENCRYPTION_KEY == generated
    assert settings.DRF_API_KEY["FERNET_SECRET"] == generated
    assert os.environ[ENCRYPTION_KEY_ENV] == generated


def test_ensure_secrets_reuses_persisted_encryption_key(monkeypatch, secrets_dir):
    persisted = _throwaway_fernet_key()
    (secrets_dir / ENCRYPTION_KEY_FILE).write_text(persisted + "\n")

    def _fail_generate():
        raise AssertionError("a persisted encryption key must not be regenerated")

    monkeypatch.setattr(
        ApiConfig, "_generate_encryption_key", staticmethod(_fail_generate)
    )

    _make_app()._ensure_secrets()

    assert settings.SECRETS_ENCRYPTION_KEY == persisted
    assert (secrets_dir / ENCRYPTION_KEY_FILE).read_text() == persisted + "\n"


def test_ensure_secrets_keeps_explicit_encryption_key(monkeypatch, secrets_dir):
    explicit = _throwaway_fernet_key()
    monkeypatch.setattr(settings, "SECRETS_ENCRYPTION_KEY", explicit, raising=False)

    _make_app()._ensure_secrets()

    assert settings.SECRETS_ENCRYPTION_KEY == explicit
    assert not (secrets_dir / ENCRYPTION_KEY_FILE).exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_ensure_secrets_refuses_empty_encryption_key_when_unpersistable(
    monkeypatch, secrets_dir
):
    secrets_dir.chmod(0o500)
    monkeypatch.setattr(
        api_apps_module, "KEYS_DIRECTORY", secrets_dir / "keys", raising=False
    )

    try:
        with pytest.raises(ImproperlyConfigured) as exc_info:
            _make_app()._ensure_secrets()
    finally:
        secrets_dir.chmod(0o700)

    assert ENCRYPTION_KEY_ENV in str(exc_info.value)
    assert settings.SECRETS_ENCRYPTION_KEY == ""


def test_ensure_secrets_recovers_when_another_process_wrote_the_key_first(
    monkeypatch, secrets_dir
):
    winner = _throwaway_fernet_key()
    real_open = os.open

    def _lose_the_race(path, flags, *args):
        if Path(path).name == ENCRYPTION_KEY_FILE:
            (secrets_dir / ENCRYPTION_KEY_FILE).write_text(winner)
        return real_open(path, flags, *args)

    monkeypatch.setattr(api_apps_module.os, "open", _lose_the_race)

    _make_app()._ensure_secrets()

    assert settings.SECRETS_ENCRYPTION_KEY == winner


def test_ensure_secrets_generates_secret_key_when_empty(monkeypatch, secrets_dir):
    monkeypatch.setattr(
        settings, "SECRETS_ENCRYPTION_KEY", _throwaway_fernet_key(), raising=False
    )

    _make_app()._ensure_secrets()

    generated = (secrets_dir / SECRET_KEY_FILE).read_text()
    assert len(generated) == 50
    assert settings.SECRET_KEY == generated
    assert os.environ[SECRET_KEY_ENV] == generated


def test_ensure_secrets_keeps_explicit_secret_key(monkeypatch, secrets_dir):
    monkeypatch.setattr(
        settings, "SECRETS_ENCRYPTION_KEY", _throwaway_fernet_key(), raising=False
    )
    monkeypatch.setenv(SECRET_KEY_ENV, "explicit-throwaway-secret-key")

    _make_app()._ensure_secrets()

    assert not (secrets_dir / SECRET_KEY_FILE).exists()


def test_ensure_secrets_is_skipped_while_testing(monkeypatch, secrets_dir):
    monkeypatch.setattr(settings, "TESTING", True, raising=False)

    _make_app()._ensure_secrets()

    assert not (secrets_dir / ENCRYPTION_KEY_FILE).exists()
    assert not (secrets_dir / SECRET_KEY_FILE).exists()


def test_import_models_settles_secrets_before_loading_models(monkeypatch):
    calls = []
    monkeypatch.setattr(
        ApiConfig, "_ensure_secrets", lambda self: calls.append("secrets")
    )
    monkeypatch.setattr(AppConfig, "import_models", lambda self: calls.append("models"))

    _make_app().import_models()

    assert calls == ["secrets", "models"]
