from unittest.mock import MagicMock, patch

import pytest
from allauth.socialaccount.models import SocialLogin
from django.contrib.auth import get_user_model

from api.account_bootstrap import provision_default_tenant_access
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Membership, Role, UserRoleRelationship
from api.adapters import ProwlerSocialAccountAdapter

User = get_user_model()


@pytest.mark.django_db
class TestProwlerSocialAccountAdapter:
    def test_get_user_by_email_returns_user(self, create_test_user):
        adapter = ProwlerSocialAccountAdapter()
        user = adapter.get_user_by_email(create_test_user.email)
        assert user == create_test_user

    def test_get_user_by_email_returns_none_for_unknown_email(self):
        adapter = ProwlerSocialAccountAdapter()
        assert adapter.get_user_by_email("notfound@example.com") is None

    def test_pre_social_login_links_existing_user(self, create_test_user, rf):
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.user = create_test_user
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        call_args = sociallogin.connect.call_args
        assert call_args is not None

        called_request, called_user = call_args[0]
        assert called_request.path == "/"
        assert called_user.email == create_test_user.email

    def test_pre_social_login_no_link_if_email_missing(self, rf):
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.provider = MagicMock()
        sociallogin.user = MagicMock()
        sociallogin.provider.id = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_save_user_saml_sets_session_flag(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.get("/")
        request.session = {}

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "saml"
        sociallogin.account = MagicMock()
        sociallogin.account.extra_data = {}

        mock_user = MagicMock()
        mock_user.id = 123

        with patch("api.adapters.super") as mock_super:
            with patch("api.adapters.transaction"):
                with patch("api.adapters.MainRouter"):
                    mock_super.return_value.save_user.return_value = mock_user
                    adapter.save_user(request, sociallogin)
                    assert request.session["saml_user_created"] == "123"

    def test_save_user_non_saml_bootstraps_default_tenant_access(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.get("/")
        request.session = {}

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "google"
        sociallogin.account = MagicMock()
        sociallogin.account.extra_data = {"name": "Test User"}

        mock_user = MagicMock()
        mock_user.id = 123

        with patch("api.adapters.super") as mock_super:
            with patch("api.adapters.transaction"):
                with patch("api.adapters.provision_default_tenant_access") as mock_bootstrap:
                    mock_super.return_value.save_user.return_value = mock_user

                    adapter.save_user(request, sociallogin)

        mock_bootstrap.assert_called_once_with(mock_user)


@pytest.mark.django_db
class TestProvisionDefaultTenantAccess:
    def test_creates_owner_membership_and_admin_role(self):
        user = User.objects.db_manager(MainRouter.admin_db).create_user(
            name="tester",
            email="bootstrap@example.com",
        )

        tenant = provision_default_tenant_access(user)

        membership = Membership.objects.using(MainRouter.admin_db).get(
            user=user, tenant=tenant
        )

        assert membership.role == Membership.RoleChoices.OWNER

        with rls_transaction(str(tenant.id), using=MainRouter.admin_db):
            role = Role.objects.using(MainRouter.admin_db).get(
                tenant_id=tenant.id, name="admin"
            )
            assert role.manage_users is True

            relationship = UserRoleRelationship.objects.using(
                MainRouter.admin_db
            ).get(user=user, tenant_id=tenant.id)
            assert relationship.role_id == role.id

    def test_creates_member_membership_and_read_role(self):
        user = User.objects.db_manager(MainRouter.admin_db).create_user(
            name="reader",
            email="reader@example.com",
        )

        tenant = provision_default_tenant_access(user, role_name="read")

        membership = Membership.objects.using(MainRouter.admin_db).get(
            user=user, tenant=tenant
        )

        assert membership.role == Membership.RoleChoices.MEMBER

        with rls_transaction(str(tenant.id), using=MainRouter.admin_db):
            role = Role.objects.using(MainRouter.admin_db).get(
                tenant_id=tenant.id, name="read"
            )
            assert role.manage_users is False
            assert role.manage_account is False
            assert role.manage_billing is False
            assert role.manage_providers is False
            assert role.manage_integrations is False
            assert role.manage_scans is False
            assert role.unlimited_visibility is True

            relationship = UserRoleRelationship.objects.using(
                MainRouter.admin_db
            ).get(user=user, tenant_id=tenant.id)
            assert relationship.role_id == role.id
