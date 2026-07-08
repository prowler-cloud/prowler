from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from allauth.socialaccount.models import SocialLogin
from api.adapters import ProwlerSocialAccountAdapter
from api.db_router import MainRouter
from api.models import Invitation, Membership, SAMLConfiguration, Tenant
from django.contrib.auth import get_user_model

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
    sociallogin.provider = MagicMock()
    sociallogin.provider.id = "saml"
    sociallogin.account.extra_data = {}
    sociallogin.user = user
    sociallogin.connect = MagicMock()
    return sociallogin


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
        sociallogin.provider = MagicMock()
        sociallogin.user = MagicMock()
        sociallogin.user.email = ""
        sociallogin.provider.id = "saml"
        sociallogin.account.extra_data = {}
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(_saml_request(rf, "prowler.com"), sociallogin)

        sociallogin.connect.assert_not_called()

    def test_pre_social_login_non_saml_links_by_email(self, create_test_user, rf):
        """Non-SAML providers (e.g. Google/GitHub) still link to an existing
        local account by email; the tenant binding only applies to SAML."""
        adapter = ProwlerSocialAccountAdapter()

        sociallogin = MagicMock(spec=SocialLogin)
        sociallogin.account = MagicMock()
        sociallogin.provider = MagicMock()
        sociallogin.provider.id = "google"
        sociallogin.account.extra_data = {"email": create_test_user.email}
        sociallogin.user = create_test_user
        sociallogin.connect = MagicMock()

        adapter.pre_social_login(rf.get("/"), sociallogin)

        call_args = sociallogin.connect.call_args
        assert call_args is not None
        _, called_user = call_args[0]
        assert called_user.email == create_test_user.email

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
