from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from allauth.account import app_settings as account_app_settings
from allauth.account.models import EmailAddress
from allauth.core import context
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount import app_settings as socialaccount_app_settings
from allauth.socialaccount.internal.flows.login import complete_login
from allauth.socialaccount.models import SocialAccount, SocialLogin
from api.adapters import ProwlerSocialAccountAdapter
from api.db_router import MainRouter, get_write_db_alias
from api.models import Invitation, Membership, SAMLConfiguration, Tenant
from django.contrib.auth import get_user_model
from django.core import mail
from django.db import connections
from django.db import router as django_router

User = get_user_model()

# Minimal, well-formed IdP metadata accepted by SAMLConfiguration._parse_metadata.
VALID_METADATA = """<?xml version='1.0' encoding='UTF-8'?>
<md:EntityDescriptor entityID='TEST' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>
<md:IDPSSODescriptor WantAuthnRequestsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
    <md:KeyDescriptor use='signing'>
    <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
        <ds:X509Data>
        <ds:X509Certificate>FAKECERTDATA</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://idp.test/sso'/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def _saml_request(rf, organization_slug):
    """Build an ACS request whose resolver_match carries the organization slug,
    mirroring how Django populates it after routing the SAML ACS URL."""
    request = rf.post(f"/api/v1/accounts/saml/{organization_slug}/acs/finish/")
    request.resolver_match = SimpleNamespace(
        kwargs={"organization_slug": organization_slug}
    )
    return request


def _saml_sociallogin(user):
    sociallogin = MagicMock(spec=SocialLogin)
    sociallogin.account = MagicMock()
    sociallogin.account.pk = None
    sociallogin.provider = MagicMock()
    sociallogin.provider.id = "saml"
    sociallogin.account.extra_data = {}
    sociallogin.user = user
    sociallogin.connect = MagicMock()
    return sociallogin


def _oauth_sociallogin(
    user,
    *,
    provider="google",
    provider_email_verified=True,
    include_extra_email=True,
):
    sociallogin = MagicMock(spec=SocialLogin)
    sociallogin.account = MagicMock()
    sociallogin.account.pk = None
    sociallogin.provider = MagicMock()
    sociallogin.provider.id = provider
    sociallogin.account.extra_data = (
        {"email": user.email} if include_extra_email else {}
    )
    sociallogin.email_addresses = [
        EmailAddress(
            email=user.email,
            verified=provider_email_verified,
            primary=True,
        )
    ]
    sociallogin.user = user
    sociallogin.connect = MagicMock()
    return sociallogin


def _real_oauth_sociallogin(user, uid):
    provider = MagicMock()
    provider.id = "google"
    provider.app = None
    provider.get_settings.return_value = {}
    return SocialLogin(
        user=user,
        account=SocialAccount(
            provider="google",
            uid=uid,
            extra_data={"email": user.email},
        ),
        email_addresses=[EmailAddress(email=user.email, verified=True, primary=True)],
        provider=provider,
    )


def _verify_local_email(user):
    return EmailAddress.objects.create(
        user=user,
        email=user.email,
        verified=True,
        primary=True,
    )


def test_social_account_name_falls_back_to_login_for_blank_name():
    adapter = ProwlerSocialAccountAdapter()

    name = adapter._get_social_account_name(
        {"name": "   ", "login": "octocat"},
        "verified@example.com",
    )

    assert name == "octocat"


@pytest.mark.parametrize("provider_name", [None, "", "   ", 123, ["name"]])
def test_social_account_name_ignores_unusable_provider_names(provider_name):
    adapter = ProwlerSocialAccountAdapter()

    name = adapter._get_social_account_name(
        {"name": provider_name, "login": "octocat"},
        "verified@example.com",
    )

    assert name == "octocat"


def test_social_account_name_uses_login_when_name_is_missing():
    adapter = ProwlerSocialAccountAdapter()

    name = adapter._get_social_account_name(
        {"login": "octocat"},
        "verified@example.com",
    )

    assert name == "octocat"


def test_social_account_name_falls_back_to_username_then_email():
    adapter = ProwlerSocialAccountAdapter()

    username_name = adapter._get_social_account_name(
        {"name": "ab", "login": None, "username": "  monalisa  "},
        "verified@example.com",
    )
    email_name = adapter._get_social_account_name({}, "  verified@example.com  ")

    assert username_name == "monalisa"
    assert email_name == "verified@example.com"


def test_social_account_name_trims_and_limits_provider_name():
    adapter = ProwlerSocialAccountAdapter()
    max_length = User._meta.get_field("name").max_length

    trimmed_name = adapter._get_social_account_name(
        {"name": "  Ada Lovelace  "},
        "verified@example.com",
    )
    limited_name = adapter._get_social_account_name(
        {"name": "a" * (max_length + 1)},
        "verified@example.com",
    )

    assert trimmed_name == "Ada Lovelace"
    assert limited_name == "a" * max_length


def test_social_account_name_rejects_missing_identity():
    adapter = ProwlerSocialAccountAdapter()

    with pytest.raises(
        ValueError,
        match="Social account does not provide a valid user identity",
    ):
        adapter._get_social_account_name({}, "")


def test_save_user_applies_normalized_social_account_name(rf):
    adapter = ProwlerSocialAccountAdapter()
    request = rf.post("/")
    request.session = {}
    sociallogin = MagicMock(spec=SocialLogin)
    sociallogin.provider = MagicMock()
    sociallogin.provider.id = "github"
    sociallogin.account = MagicMock()
    sociallogin.account.extra_data = {"name": None, "login": "  octocat  "}
    user = User(email="verified@example.com")
    user.save = MagicMock()
    invitation = SimpleNamespace(tenant_id="tenant-id")

    with (
        patch("api.adapters.super") as mock_super,
        patch("api.adapters.transaction.atomic"),
        patch("api.adapters.write_db_alias"),
        patch.object(adapter, "_get_invitation_token", return_value="token"),
        patch(
            "api.adapters.accept_invitation_for_user",
            return_value=(invitation, True),
        ),
    ):
        mock_super.return_value.save_user.return_value = user
        saved_user = adapter.save_user(request, sociallogin)

    assert saved_user.name == "octocat"
    assert request.prowler_invitation_token == "token"


@pytest.mark.django_db
class TestProwlerSocialAccountAdapter:
    def test_get_user_by_email_returns_user(self, create_test_user):
        adapter = ProwlerSocialAccountAdapter()
        user = adapter.get_user_by_email(create_test_user.email)
        assert user == create_test_user

    def test_get_user_by_email_returns_none_for_unknown_email(self):
        adapter = ProwlerSocialAccountAdapter()
        assert adapter.get_user_by_email("notfound@example.com") is None

    def test_pre_social_login_links_member_of_saml_tenant(
        self, create_test_user, tenants_fixture, rf
    ):
        """A SAML login links to an existing account only when that user is
        already a member of the tenant that owns the asserted email domain."""
        adapter = ProwlerSocialAccountAdapter()
        # create_test_user (dev@prowler.com) is a member of tenant1.
        domain = create_test_user.email.rsplit("@", 1)[-1]
        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain=domain,
            metadata_xml=VALID_METADATA,
            tenant=tenants_fixture[0],
        )

        sociallogin = _saml_sociallogin(create_test_user)
        adapter.pre_social_login(_saml_request(rf, domain), sociallogin)

        call_args = sociallogin.connect.call_args
        assert call_args is not None
        _, called_user = call_args[0]
        assert called_user.email == create_test_user.email

    def test_pre_social_login_blocks_cross_tenant_takeover(
        self, create_test_user, tenants_fixture, rf
    ):
        """GHSA-h8m9-jgf8-vwvp: an attacker tenant that claims the victim's
        email domain must NOT be able to link to the victim's account, because
        the victim is not a member of the attacker's tenant."""
        adapter = ProwlerSocialAccountAdapter()
        domain = create_test_user.email.rsplit("@", 1)[-1]
        # tenant3 is the attacker tenant; create_test_user is NOT a member of it.
        attacker_tenant = tenants_fixture[2]
        assert not create_test_user.is_member_of_tenant(str(attacker_tenant.id))
        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain=domain,
            metadata_xml=VALID_METADATA,
            tenant=attacker_tenant,
        )

        sociallogin = _saml_sociallogin(create_test_user)
        adapter.pre_social_login(_saml_request(rf, domain), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_blocks_domain_slug_mismatch(
        self, create_test_user, tenants_fixture, rf
    ):
        """The asserted email domain must match the ACS endpoint's slug, so an
        assertion cannot be replayed through a different tenant's endpoint."""
        adapter = ProwlerSocialAccountAdapter()
        domain = create_test_user.email.rsplit("@", 1)[-1]
        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain=domain,
            metadata_xml=VALID_METADATA,
            tenant=tenants_fixture[0],
        )

        sociallogin = _saml_sociallogin(create_test_user)
        # Slug points at a different domain than the asserted email.
        adapter.pre_social_login(_saml_request(rf, "attacker.com"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_blocks_when_no_saml_config(
        self, create_test_user, tenants_fixture, rf
    ):
        """No SAML configuration for the domain means nothing to link against."""
        adapter = ProwlerSocialAccountAdapter()
        domain = create_test_user.email.rsplit("@", 1)[-1]

        sociallogin = _saml_sociallogin(create_test_user)
        adapter.pre_social_login(_saml_request(rf, domain), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_blocks_without_resolver_match(
        self, create_test_user, tenants_fixture, rf
    ):
        """Fail closed: if the request has no resolver_match we cannot bind the
        assertion to a tenant, so no linking happens."""
        adapter = ProwlerSocialAccountAdapter()
        domain = create_test_user.email.rsplit("@", 1)[-1]
        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain=domain,
            metadata_xml=VALID_METADATA,
            tenant=tenants_fixture[0],
        )

        sociallogin = _saml_sociallogin(create_test_user)
        adapter.pre_social_login(rf.post("/"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_no_link_if_email_missing(self, rf):
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.account.pk = None
        sociallogin.provider = MagicMock()
        sociallogin.user = MagicMock()
        sociallogin.user.email = ""
        sociallogin.provider.id = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(_saml_request(rf, "prowler.com"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_blocks_unverified_local_email(self, create_test_user, rf):
        """A verified OAuth email must not claim an unverified local account."""
        adapter = ProwlerSocialAccountAdapter()
        sociallogin = _oauth_sociallogin(create_test_user)

        with pytest.raises(ImmediateHttpResponse) as exc_info:
            adapter.pre_social_login(rf.get("/"), sociallogin)

        assert exc_info.value.response.status_code == 403
        sociallogin.connect.assert_not_called()

    def test_complete_oauth_login_does_not_link_unverified_local_email(
        self, create_test_user, rf
    ):
        """Regression test for the complete pre-hijack account-linking flow."""
        incoming_user = User(email=create_test_user.email)
        incoming_user.set_unusable_password()
        sociallogin = _real_oauth_sociallogin(
            incoming_user,
            uid="victim-google-account",
        )
        request = rf.get("/")
        request.session = {}

        with pytest.raises(ImmediateHttpResponse) as exc_info:
            complete_login(request, sociallogin, raises=True)

        assert exc_info.value.response.status_code == 403
        assert not SocialAccount.objects.filter(
            provider="google", uid="victim-google-account"
        ).exists()

    def test_pre_social_login_allows_already_connected_account(
        self, create_test_user, rf
    ):
        """Existing provider bindings do not need to relink on every login."""
        adapter = ProwlerSocialAccountAdapter()
        sociallogin = _oauth_sociallogin(create_test_user)
        sociallogin.account.pk = "existing-social-account"

        adapter.pre_social_login(rf.get("/"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_blocks_unverified_provider_email(
        self, create_test_user, rf
    ):
        """An OAuth provider must prove ownership of the matching email."""
        _verify_local_email(create_test_user)
        adapter = ProwlerSocialAccountAdapter()
        sociallogin = _oauth_sociallogin(
            create_test_user,
            provider="github",
            provider_email_verified=False,
        )

        with pytest.raises(ImmediateHttpResponse) as exc_info:
            adapter.pre_social_login(rf.get("/"), sociallogin)

        assert exc_info.value.response.status_code == 403
        sociallogin.connect.assert_not_called()

    def test_pre_social_login_links_verified_emails(self, create_test_user, rf):
        _verify_local_email(create_test_user)
        adapter = ProwlerSocialAccountAdapter()
        sociallogin = _oauth_sociallogin(create_test_user)
        request = rf.get("/")

        adapter.pre_social_login(request, sociallogin)

        sociallogin.connect.assert_called_once_with(request, create_test_user)

    def test_verified_social_account_link_does_not_send_notification(
        self, create_test_user, rf
    ):
        _verify_local_email(create_test_user)
        sociallogin = _real_oauth_sociallogin(
            create_test_user,
            uid="verified-google-account",
        )

        request = rf.get("/")
        with context.request_context(request):
            ProwlerSocialAccountAdapter().pre_social_login(request, sociallogin)

        assert SocialAccount.objects.filter(
            provider="google",
            uid="verified-google-account",
            user=create_test_user,
        ).exists()
        assert mail.outbox == []

    def test_pre_social_login_uses_verified_email_missing_from_extra_data(
        self, create_test_user, rf
    ):
        """GitHub can return its verified primary email outside extra_data."""
        _verify_local_email(create_test_user)
        adapter = ProwlerSocialAccountAdapter()
        sociallogin = _oauth_sociallogin(
            create_test_user,
            provider="github",
            include_extra_email=False,
        )
        request = rf.get("/")

        adapter.pre_social_login(request, sociallogin)

        sociallogin.connect.assert_called_once_with(request, create_test_user)

    def test_social_account_linking_settings_are_fail_closed(self):
        assert not socialaccount_app_settings.EMAIL_AUTHENTICATION
        assert not socialaccount_app_settings.EMAIL_AUTHENTICATION_AUTO_CONNECT
        assert not account_app_settings.EMAIL_NOTIFICATIONS

    def test_save_user_social_with_invitation_joins_invited_tenant(
        self, rf, create_test_user, tenants_fixture
    ):
        adapter = ProwlerSocialAccountAdapter()
        invited_tenant = tenants_fixture[2]
        invited_email = "frank-invited@example.com"
        invitation = Invitation.objects.create(
            tenant=invited_tenant,
            email=invited_email,
            inviter=create_test_user,
        )
        request = rf.post("/", data={"invitation_token": invitation.token})
        request.session = {}

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "google"
        sociallogin.account = MagicMock()
        sociallogin.account.extra_data = {"name": "Frank"}

        real_user = User.objects.create_user(
            name="Frank", email=invited_email, password="Secret123!"
        )
        tenants_before = Tenant.objects.count()

        with patch("api.adapters.super") as mock_super:
            mock_super.return_value.save_user.return_value = real_user
            adapter.save_user(request, sociallogin)

        invitation.refresh_from_db()
        assert invitation.state == Invitation.State.ACCEPTED
        assert Tenant.objects.count() == tenants_before
        assert Membership.objects.filter(
            user=real_user,
            tenant=invited_tenant,
            role=Membership.RoleChoices.MEMBER,
        ).exists()

    def test_save_user_routes_initial_allauth_write_to_admin_and_resets_on_error(
        self, rf
    ):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.get("/")
        request.session = {}
        sociallogin = _oauth_sociallogin(
            User(name="Frank", email="frank-routing@example.com")
        )

        def fail_after_checking_write_route(*_args, **_kwargs):
            assert (
                MainRouter().db_for_write(User, instance=sociallogin.user)
                == MainRouter.admin_db
            )
            raise RuntimeError("Stop after checking the write route.")

        with (
            patch("api.adapters.super") as mock_super,
            patch("api.adapters.transaction.atomic"),
            patch.object(MainRouter, "admin_db", "admin"),
            pytest.raises(RuntimeError, match="Stop after checking the write route"),
        ):
            mock_super.return_value.save_user.side_effect = (
                fail_after_checking_write_route
            )
            adapter.save_user(request, sociallogin)

        assert get_write_db_alias() is None

    def test_save_user_rolls_back_all_signup_records_on_downstream_error(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.post("/")
        request.session = {}
        email = "frank-rollback@example.com"
        sociallogin = _real_oauth_sociallogin(
            User(name="Frank", email=email),
            uid="frank-rollback-google-account",
        )
        tenants_before = Tenant.objects.count()

        with (
            patch(
                "api.adapters.rls_transaction",
                side_effect=RuntimeError("Simulated downstream failure."),
            ),
            pytest.raises(RuntimeError, match="Simulated downstream failure"),
        ):
            adapter.save_user(request, sociallogin)

        assert not User.objects.filter(email=email).exists()
        assert not SocialAccount.objects.filter(
            provider="google",
            uid="frank-rollback-google-account",
        ).exists()
        assert not EmailAddress.objects.filter(email=email).exists()
        assert Tenant.objects.count() == tenants_before
        assert get_write_db_alias() is None

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


@pytest.mark.requires_test_admin_alias
@pytest.mark.django_db(transaction=True, databases=["default", "admin"])
class TestProwlerSocialAccountAdapterMultiDatabase:
    @staticmethod
    def _production_router():
        return patch.object(django_router, "routers", [MainRouter()])

    def test_save_user_rolls_back_across_production_database_aliases(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.post("/")
        request.session = {}
        email = "frank-multidb-rollback@example.com"
        sociallogin = _real_oauth_sociallogin(
            User(name="Frank", email=email),
            uid="frank-multidb-rollback-google-account",
        )
        tenants_before = Tenant.objects.using("admin").count()

        assert connections["default"] is not connections["admin"]
        assert (
            connections["default"].settings_dict["NAME"]
            == connections["admin"].settings_dict["NAME"]
        )

        def fail_after_allauth_save(*_args, **_kwargs):
            assert sociallogin.user._state.db == MainRouter.admin_db
            assert connections["default"].get_autocommit()
            assert not connections["admin"].get_autocommit()
            raise RuntimeError("Simulated downstream failure.")

        with (
            patch.object(MainRouter, "admin_db", "admin"),
            self._production_router(),
            patch("api.adapters.rls_transaction", side_effect=fail_after_allauth_save),
            pytest.raises(RuntimeError, match="Simulated downstream failure"),
        ):
            adapter.save_user(request, sociallogin)

        assert connections["default"].get_autocommit()
        assert connections["admin"].get_autocommit()
        assert not User.objects.using("default").filter(email=email).exists()
        assert not User.objects.using("admin").filter(email=email).exists()
        assert (
            not SocialAccount.objects.using("admin")
            .filter(
                provider="google",
                uid="frank-multidb-rollback-google-account",
            )
            .exists()
        )
        assert not EmailAddress.objects.using("admin").filter(email=email).exists()
        assert Tenant.objects.using("admin").count() == tenants_before
        assert get_write_db_alias() is None

    def test_save_user_commits_complete_signup_across_production_aliases(self, rf):
        adapter = ProwlerSocialAccountAdapter()
        request = rf.post("/")
        request.session = {}
        email = "frank-multidb-success@example.com"
        sociallogin = _real_oauth_sociallogin(
            User(name="Frank", email=email),
            uid="frank-multidb-success-google-account",
        )

        with (
            patch.object(MainRouter, "admin_db", "admin"),
            self._production_router(),
        ):
            user = adapter.save_user(request, sociallogin)

        user = User.objects.using("admin").get(id=user.id)
        assert user.email == email
        assert (
            SocialAccount.objects.using("admin")
            .filter(
                user_id=user.id,
                provider="google",
                uid="frank-multidb-success-google-account",
            )
            .exists()
        )
        assert (
            EmailAddress.objects.using("admin")
            .filter(
                user_id=user.id,
                email=email,
                verified=True,
            )
            .exists()
        )
        assert (
            Membership.objects.using("admin")
            .filter(
                user_id=user.id,
                role=Membership.RoleChoices.OWNER,
            )
            .exists()
        )
        assert get_write_db_alias() is None
