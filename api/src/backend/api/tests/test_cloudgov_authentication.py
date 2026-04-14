from unittest.mock import patch

import pytest
from django.test import override_settings

from api.cloudgov.authentication import ProwlerUaaBackend


@pytest.mark.django_db
class TestProwlerUaaBackend:
    @override_settings(
        UAA_EMAIL_ROLE_MAP={
            "editor": ["editor@example.com"],
            "read": ["reader@example.com"],
        }
    )
    def test_get_role_name_for_email_uses_configured_mapping(self):
        assert ProwlerUaaBackend.get_role_name_for_email("EDITOR@example.com") == "editor"
        assert ProwlerUaaBackend.get_role_name_for_email("reader@example.com") == "read"

    @override_settings(UAA_EMAIL_ROLE_MAP={"read": ["reader@example.com"]})
    def test_get_role_name_for_email_defaults_to_admin(self):
        assert ProwlerUaaBackend.get_role_name_for_email("other@example.com") == "admin"

    def test_create_user_with_email_bootstraps_default_tenant_access(self):
        with patch(
            "api.cloudgov.authentication.provision_default_tenant_access"
        ) as mock_bootstrap:
            user = ProwlerUaaBackend.create_user_with_email("person@example.com")

        assert user.email == "person@example.com"
        assert user.name == "person"
        mock_bootstrap.assert_called_once_with(user)

    @override_settings(UAA_EMAIL_ROLE_MAP={"read": ["reader@example.com"]})
    def test_create_user_with_email_bootstraps_mapped_role(self):
        with patch(
            "api.cloudgov.authentication.provision_default_tenant_access"
        ) as mock_bootstrap:
            user = ProwlerUaaBackend.create_user_with_email("reader@example.com")

        mock_bootstrap.assert_called_once_with(user, role_name="read")

    def test_create_user_with_short_local_part_uses_valid_name(self):
        with patch(
            "api.cloudgov.authentication.provision_default_tenant_access"
        ):
            user = ProwlerUaaBackend.create_user_with_email("ab@example.com")

        assert user.name == "ab user"