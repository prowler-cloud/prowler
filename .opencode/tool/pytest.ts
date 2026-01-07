
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: pytest
description: Pytest testing patterns for Python. Fixtures, mocking, markers, parametrize.
license: MIT
---

## When to use this skill

Use this skill for Python testing with pytest.

## Basic Test Structure

\`\`\`python
import pytest

class TestUserService:
    def test_create_user_success(self):
        user = create_user(name="John", email="john@test.com")
        assert user.name == "John"
        assert user.email == "john@test.com"

    def test_create_user_invalid_email_fails(self):
        with pytest.raises(ValueError, match="Invalid email"):
            create_user(name="John", email="invalid")
\`\`\`

## Fixtures

\`\`\`python
import pytest

@pytest.fixture
def user():
    return User(name="Test User", email="test@example.com")

@pytest.fixture
def authenticated_client(client, user):
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
@pytest.fixture(scope="module")   # Once per module
@pytest.fixture(scope="session")  # Once per test session
\`\`\`

## Mocking

\`\`\`python
from unittest.mock import patch, MagicMock

def test_with_mock():
    with patch("services.payment.stripe_client") as mock_stripe:
        mock_stripe.charge.return_value = {"id": "ch_123", "status": "succeeded"}

        result = process_payment(amount=100)

        assert result["status"] == "succeeded"
        mock_stripe.charge.assert_called_once_with(amount=100)

def test_with_side_effect():
    with patch("services.payment.stripe_client") as mock_stripe:
        mock_stripe.charge.side_effect = PaymentError("Card declined")

        with pytest.raises(PaymentError):
            process_payment(amount=100)
\`\`\`

## Parametrize

\`\`\`python
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
])
def test_email_validation(email, is_valid):
    assert validate_email(email) == is_valid
\`\`\`

## Markers

\`\`\`python
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
\`\`\`

## Commands

\`\`\`bash
pytest                          # Run all tests
pytest -v                       # Verbose
pytest -x                       # Stop on first failure
pytest -k "test_user"           # Filter by name
pytest -m "not slow"            # Filter by marker
pytest --cov=src                # With coverage
pytest -n auto                  # Parallel
\`\`\`

## Keywords
pytest, python, testing, fixtures, mocking, parametrize, markers
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: fixtures, mocking, parametrize, markers, async"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("fixture")) {
      return `
## Pytest Fixtures

\`\`\`python
@pytest.fixture
def user():
    return User(name="Test", email="test@example.com")

@pytest.fixture
def db_session():
    session = create_session()
    yield session
    session.rollback()

# Scopes: function (default), class, module, session
@pytest.fixture(scope="module")
def shared_resource():
    return expensive_setup()
\`\`\`
      `.trim();
    }

    if (topic.includes("mock")) {
      return `
## Pytest Mocking

\`\`\`python
from unittest.mock import patch, MagicMock

# Patch context manager
with patch("module.function") as mock_fn:
    mock_fn.return_value = "mocked"
    result = module.function()

# Side effects
mock_fn.side_effect = Exception("Error")
mock_fn.side_effect = [1, 2, 3]  # Sequential returns

# MagicMock for objects
mock_obj = MagicMock()
mock_obj.method.return_value = "value"
mock_obj.attribute = "attr"
\`\`\`
      `.trim();
    }

    return `
## Pytest Quick Reference

1. **Fixtures**: @pytest.fixture with yield for teardown
2. **Mocking**: patch() context manager + MagicMock
3. **Parametrize**: @pytest.mark.parametrize for multiple inputs
4. **Markers**: @pytest.mark.slow, skip, skipif, integration
5. **Commands**: pytest -v -x -k "pattern" -m "marker"

Topics: fixtures, mocking, parametrize, markers, async
    `.trim();
  },
})
