from unittest.mock import MagicMock, patch

from linode_api4.errors import ApiError

from prowler.providers.linode.services.account.account_service import (
    AccountService,
)


def _mock_user(username="admin", email="admin@example.com", tfa=True, restricted=False):
    user = MagicMock()
    user.username = username
    user.email = email
    user.tfa_enabled = tfa
    user.restricted = restricted
    return user


def _build_service(account_users_return=None, account_users_side_effect=None):
    """Build an AccountService with an isolated mock client."""
    service = object.__new__(AccountService)
    service.users = []

    # Build isolated mock hierarchy for client.account.users()
    # Must explicitly create the users callable as a fresh MagicMock
    # because check tests contaminate MagicMock class with users=[...]
    users_callable = MagicMock()
    if account_users_side_effect:
        users_callable.side_effect = account_users_side_effect
    else:
        users_callable.return_value = account_users_return or []

    account_mock = MagicMock()
    account_mock.users = users_callable

    client_mock = MagicMock()
    client_mock.account = account_mock
    service.client = client_mock
    return service


class TestLinodeAccountService:
    def test_describe_users_parses_correctly(self):
        mock_users = [
            _mock_user("admin", "admin@example.com", True, False),
            _mock_user("reader", "reader@example.com", False, True),
        ]

        service = _build_service(account_users_return=mock_users)
        service._describe_users()

        assert len(service.users) == 2
        assert service.users[0].username == "admin"
        assert service.users[0].tfa_enabled is True
        assert service.users[1].username == "reader"
        assert service.users[1].restricted is True

    def test_describe_users_handles_empty_list(self):
        service = _build_service(account_users_return=[])
        service._describe_users()

        assert len(service.users) == 0

    def test_describe_users_handles_api_error(self):
        service = _build_service(account_users_side_effect=Exception("API error"))
        service._describe_users()

        assert len(service.users) == 0

    def test_describe_users_handles_null_fields(self):
        """A user with null tfa_enabled/email must still be included with safe
        defaults instead of being dropped by a ValidationError."""
        user = MagicMock()
        user.username = "partial"
        user.email = None
        user.tfa_enabled = None
        user.restricted = None

        service = _build_service(account_users_return=[user])
        service._describe_users()

        assert len(service.users) == 1
        assert service.users[0].username == "partial"
        assert service.users[0].email == ""
        assert service.users[0].tfa_enabled is False
        assert service.users[0].restricted is False

    def test_describe_users_missing_scope_logs_permission_error(self):
        error = ApiError(
            "Your OAuth token is not authorized to use this endpoint.", status=401
        )
        service = _build_service(account_users_side_effect=error)

        with patch(
            "prowler.providers.linode.lib.service.service.logger"
        ) as logger_mock:
            service._describe_users()

        assert len(service.users) == 0
        logged = " ".join(str(c) for c in logger_mock.error.call_args_list)
        assert "LinodeMissingPermissionError" in logged
        assert "account:read_only" in logged
