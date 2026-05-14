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
