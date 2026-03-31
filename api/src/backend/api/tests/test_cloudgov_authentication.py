from unittest.mock import patch

import pytest

from api.cloudgov.authentication import ProwlerUaaBackend


@pytest.mark.django_db
class TestProwlerUaaBackend:
    def test_create_user_with_email_bootstraps_default_tenant_access(self):
        with patch(
            "api.cloudgov.authentication.provision_default_tenant_access"
        ) as mock_bootstrap:
            user = ProwlerUaaBackend.create_user_with_email("person@example.com")

        assert user.email == "person@example.com"
        assert user.name == "person"
        mock_bootstrap.assert_called_once_with(user)

    def test_create_user_with_short_local_part_uses_valid_name(self):
        with patch(
            "api.cloudgov.authentication.provision_default_tenant_access"
        ):
            user = ProwlerUaaBackend.create_user_with_email("ab@example.com")

        assert user.name == "ab user"