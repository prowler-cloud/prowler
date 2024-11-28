from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.entra.entra_service import User
from prowler.providers.azure.services.entra.lib.user_privileges import (
    is_privileged_user,
)


class Test_user_privileges_test:
    def test_user_in_privileged_roles(self):
        user_id = str(uuid4())
        privileged_roles = {"admin": mock.MagicMock()}
        privileged_roles["admin"].members = [User(id=user_id, name="user1")]

        user = User(id=user_id, name="user1")
        assert is_privileged_user(user, privileged_roles)

    def test_user_not_in_privileged_roles(self):
        user_id = str(uuid4())
        privileged_roles = {"admin": mock.MagicMock()}
        privileged_roles["admin"].members = [User(id=str(uuid4()), name="user2")]

        user = User(id=user_id, name="user1")
        assert not is_privileged_user(user, privileged_roles)
