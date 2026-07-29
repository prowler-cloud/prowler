import pytest
from config.settings.celery import _build_celery_broker_url


class TestBuildCeleryBrokerUrl:
    def test_without_credentials(self):
        broker_url = _build_celery_broker_url("redis", "", "", "valkey", "6379", "0")

        assert broker_url == "redis://valkey:6379/0"

    def test_with_password_only(self):
        broker_url = _build_celery_broker_url(
            "rediss", "", "secret", "cache.example.com", "6379", "0"
        )

        assert broker_url == "rediss://:secret@cache.example.com:6379/0"

    def test_with_username_and_password(self):
        broker_url = _build_celery_broker_url(
            "rediss", "default", "secret", "cache.example.com", "6379", "0"
        )

        assert broker_url == "rediss://default:secret@cache.example.com:6379/0"

    def test_with_username_only(self):
        broker_url = _build_celery_broker_url(
            "redis", "admin", "", "valkey", "6379", "0"
        )

        assert broker_url == "redis://admin@valkey:6379/0"

    def test_url_encodes_credentials(self):
        broker_url = _build_celery_broker_url(
            "rediss", "user@name", "p@ss:word", "cache.example.com", "6379", "0"
        )

        assert (
            broker_url == "rediss://user%40name:p%40ss%3Aword@cache.example.com:6379/0"
        )

    def test_invalid_scheme_raises_error(self):
        with pytest.raises(ValueError, match="Invalid VALKEY_SCHEME 'http'"):
            _build_celery_broker_url("http", "", "", "valkey", "6379", "0")


class TestCeleryWorkerConcurrency:
    def _reimport_settings(self):
        """Fresh import — importlib.reload() doesn't clear the module namespace,
        so an attribute set by a prior test would leak into the unset case."""
        import sys

        sys.modules.pop("config.settings.celery", None)
        import config.settings.celery as celery_settings

        return celery_settings

    def test_unset_leaves_setting_absent(self, monkeypatch):
        monkeypatch.delenv("DJANGO_CELERY_WORKER_CONCURRENCY", raising=False)
        mod = self._reimport_settings()
        assert not hasattr(mod, "CELERY_WORKER_CONCURRENCY")

    def test_explicit_value_applied(self, monkeypatch):
        monkeypatch.setenv("DJANGO_CELERY_WORKER_CONCURRENCY", "8")
        mod = self._reimport_settings()
        assert mod.CELERY_WORKER_CONCURRENCY == 8

    def test_invalid_value_raises(self, monkeypatch):
        monkeypatch.setenv("DJANGO_CELERY_WORKER_CONCURRENCY", "not-a-number")
        with pytest.raises(ValueError):
            self._reimport_settings()
