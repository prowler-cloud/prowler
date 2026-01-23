"""
Tests for Neo4j database lazy initialization.

The Neo4j driver connects on first use by default. API processes may
eagerly initialize the driver during app startup, while Celery workers
remain lazy. These tests validate the database module behavior itself.
"""

import threading
from unittest.mock import MagicMock, patch

import pytest


class TestLazyInitialization:
    """Test that Neo4j driver is initialized lazily on first use."""

    @pytest.fixture(autouse=True)
    def reset_module_state(self):
        """Reset module-level singleton state before each test."""
        import api.attack_paths.database as db_module

        original_driver = db_module._driver

        db_module._driver = None

        yield

        db_module._driver = original_driver

    def test_driver_not_initialized_at_import(self):
        """Driver should be None after module import (no eager connection)."""
        import api.attack_paths.database as db_module

        assert db_module._driver is None

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_init_driver_creates_connection_on_first_call(
        self, mock_driver_factory, mock_settings
    ):
        """init_driver() should create connection only when called."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        mock_driver_factory.return_value = mock_driver
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        assert db_module._driver is None

        result = db_module.init_driver()

        mock_driver_factory.assert_called_once()
        mock_driver.verify_connectivity.assert_called_once()
        assert result is mock_driver
        assert db_module._driver is mock_driver

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_init_driver_returns_cached_driver_on_subsequent_calls(
        self, mock_driver_factory, mock_settings
    ):
        """Subsequent calls should return cached driver without reconnecting."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        mock_driver_factory.return_value = mock_driver
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        first_result = db_module.init_driver()
        second_result = db_module.init_driver()
        third_result = db_module.init_driver()

        # Only one connection attempt
        assert mock_driver_factory.call_count == 1
        assert mock_driver.verify_connectivity.call_count == 1

        # All calls return same instance
        assert first_result is second_result is third_result

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_get_driver_delegates_to_init_driver(
        self, mock_driver_factory, mock_settings
    ):
        """get_driver() should use init_driver() for lazy initialization."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        mock_driver_factory.return_value = mock_driver
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        result = db_module.get_driver()

        assert result is mock_driver
        mock_driver_factory.assert_called_once()


class TestAtexitRegistration:
    """Test that atexit cleanup handler is registered correctly."""

    @pytest.fixture(autouse=True)
    def reset_module_state(self):
        """Reset module-level singleton state before each test."""
        import api.attack_paths.database as db_module

        original_driver = db_module._driver

        db_module._driver = None

        yield

        db_module._driver = original_driver

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.atexit.register")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_atexit_registered_on_first_init(
        self, mock_driver_factory, mock_atexit_register, mock_settings
    ):
        """atexit.register should be called on first initialization."""
        import api.attack_paths.database as db_module

        mock_driver_factory.return_value = MagicMock()
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        db_module.init_driver()

        mock_atexit_register.assert_called_once_with(db_module.close_driver)

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.atexit.register")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_atexit_registered_only_once(
        self, mock_driver_factory, mock_atexit_register, mock_settings
    ):
        """atexit.register should only be called once across multiple inits.

        The double-checked locking on _driver ensures the atexit registration
        block only executes once (when _driver is first created).
        """
        import api.attack_paths.database as db_module

        mock_driver_factory.return_value = MagicMock()
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        db_module.init_driver()
        db_module.init_driver()
        db_module.init_driver()

        # Only registered once because subsequent calls hit the fast path
        assert mock_atexit_register.call_count == 1


class TestCloseDriver:
    """Test driver cleanup functionality."""

    @pytest.fixture(autouse=True)
    def reset_module_state(self):
        """Reset module-level singleton state before each test."""
        import api.attack_paths.database as db_module

        original_driver = db_module._driver

        db_module._driver = None

        yield

        db_module._driver = original_driver

    def test_close_driver_closes_and_clears_driver(self):
        """close_driver() should close the driver and set it to None."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        db_module._driver = mock_driver

        db_module.close_driver()

        mock_driver.close.assert_called_once()
        assert db_module._driver is None

    def test_close_driver_handles_none_driver(self):
        """close_driver() should handle case where driver is None."""
        import api.attack_paths.database as db_module

        db_module._driver = None

        # Should not raise
        db_module.close_driver()

        assert db_module._driver is None

    def test_close_driver_clears_driver_even_on_close_error(self):
        """Driver should be cleared even if close() raises an exception."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        mock_driver.close.side_effect = Exception("Connection error")
        db_module._driver = mock_driver

        with pytest.raises(Exception, match="Connection error"):
            db_module.close_driver()

        # Driver should still be cleared
        assert db_module._driver is None


class TestThreadSafety:
    """Test thread-safe initialization."""

    @pytest.fixture(autouse=True)
    def reset_module_state(self):
        """Reset module-level singleton state before each test."""
        import api.attack_paths.database as db_module

        original_driver = db_module._driver

        db_module._driver = None

        yield

        db_module._driver = original_driver

    @patch("api.attack_paths.database.settings")
    @patch("api.attack_paths.database.neo4j.GraphDatabase.driver")
    def test_concurrent_init_creates_single_driver(
        self, mock_driver_factory, mock_settings
    ):
        """Multiple threads calling init_driver() should create only one driver."""
        import api.attack_paths.database as db_module

        mock_driver = MagicMock()
        mock_driver_factory.return_value = mock_driver
        mock_settings.DATABASES = {
            "neo4j": {
                "HOST": "localhost",
                "PORT": 7687,
                "USER": "neo4j",
                "PASSWORD": "password",
            }
        }

        results = []
        errors = []

        def call_init():
            try:
                result = db_module.init_driver()
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=call_init) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Threads raised errors: {errors}"

        # Only one driver created
        assert mock_driver_factory.call_count == 1

        # All threads got the same driver instance
        assert all(r is mock_driver for r in results)
        assert len(results) == 10
