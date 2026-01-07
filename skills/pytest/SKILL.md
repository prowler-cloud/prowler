---
name: pytest
description: >
  Pytest testing patterns for Python.
  Trigger: When writing Python tests - fixtures, mocking, markers.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## Basic Test Structure

```python
import pytest

class TestUserService:
    def test_create_user_success(self):
        user = create_user(name="John", email="john@test.com")
        assert user.name == "John"
        assert user.email == "john@test.com"

    def test_create_user_invalid_email_fails(self):
        with pytest.raises(ValueError, match="Invalid email"):
            create_user(name="John", email="invalid")
```

## Fixtures

```python
import pytest

@pytest.fixture
def user():
    """Create a test user."""
    return User(name="Test User", email="test@example.com")

@pytest.fixture
def authenticated_client(client, user):
    """Client with authenticated user."""
    client.force_login(user)
    return client

# Fixture with teardown
@pytest.fixture
def temp_file():
    path = Path("/tmp/test_file.txt")
    path.write_text("test content")
    yield path  # Test runs here
    path.unlink()  # Cleanup after test

# Fixture scopes
@pytest.fixture(scope="module")  # Once per module
@pytest.fixture(scope="class")   # Once per class
@pytest.fixture(scope="session") # Once per test session
```

## conftest.py

```python
# tests/conftest.py - Shared fixtures
import pytest

@pytest.fixture
def db_session():
    session = create_session()
    yield session
    session.rollback()

@pytest.fixture
def api_client():
    return TestClient(app)
```

## Mocking

```python
from unittest.mock import patch, MagicMock

class TestPaymentService:
    def test_process_payment_success(self):
        with patch("services.payment.stripe_client") as mock_stripe:
            mock_stripe.charge.return_value = {"id": "ch_123", "status": "succeeded"}

            result = process_payment(amount=100)

            assert result["status"] == "succeeded"
            mock_stripe.charge.assert_called_once_with(amount=100)

    def test_process_payment_failure(self):
        with patch("services.payment.stripe_client") as mock_stripe:
            mock_stripe.charge.side_effect = PaymentError("Card declined")

            with pytest.raises(PaymentError):
                process_payment(amount=100)

# MagicMock for complex objects
def test_with_mock_object():
    mock_user = MagicMock()
    mock_user.id = "user-123"
    mock_user.name = "Test User"
    mock_user.is_active = True

    result = get_user_info(mock_user)
    assert result["name"] == "Test User"
```

## Parametrize

```python
@pytest.mark.parametrize("input,expected", [
    ("hello", "HELLO"),
    ("world", "WORLD"),
    ("pytest", "PYTEST"),
])
def test_uppercase(input, expected):
    assert input.upper() == expected

@pytest.mark.parametrize("email,is_valid", [
    ("user@example.com", True),
    ("invalid-email", False),
    ("", False),
    ("user@.com", False),
])
def test_email_validation(email, is_valid):
    assert validate_email(email) == is_valid
```

## Markers

```python
# pytest.ini or pyproject.toml
[tool.pytest.ini_options]
markers = [
    "slow: marks tests as slow",
    "integration: marks integration tests",
]

# Usage
@pytest.mark.slow
def test_large_data_processing():
    ...

@pytest.mark.integration
def test_database_connection():
    ...

@pytest.mark.skip(reason="Not implemented yet")
def test_future_feature():
    ...

@pytest.mark.skipif(sys.platform == "win32", reason="Unix only")
def test_unix_specific():
    ...

# Run specific markers
# pytest -m "not slow"
# pytest -m "integration"
```

## Async Tests

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_fetch_data()
    assert result is not None
```

## Commands

```bash
pytest                          # Run all tests
pytest -v                       # Verbose output
pytest -x                       # Stop on first failure
pytest -k "test_user"           # Filter by name
pytest -m "not slow"            # Filter by marker
pytest --cov=src                # With coverage
pytest -n auto                  # Parallel (pytest-xdist)
pytest --tb=short               # Short traceback
```

## Keywords
pytest, python, testing, fixtures, mocking, parametrize, markers
