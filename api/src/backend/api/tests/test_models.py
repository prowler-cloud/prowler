import pytest
from allauth.socialaccount.models import SocialApp
from django.core.exceptions import ValidationError

from api.db_router import MainRouter
from api.models import (
    Resource,
    ResourceTag,
    SAMLConfigurations,
    SAMLDomainIndex,
    Tenant,
)

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


@pytest.mark.django_db
class TestResourceModel:
    def test_setting_tags(self, providers_fixture):
        provider, *_ = providers_fixture
        tenant_id = provider.tenant_id

        resource = Resource.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            name="My Instance 1",
            region="us-east-1",
            service="ec2",
            type="prowler-test",
        )

        tags = [
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="key",
                value="value",
            ),
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="key2",
                value="value2",
            ),
        ]

        resource.upsert_or_delete_tags(tags)

        assert len(tags) == len(resource.tags.filter(tenant_id=tenant_id))

        tags_dict = resource.get_tags(tenant_id=tenant_id)

        for tag in tags:
            assert tag.key in tags_dict
            assert tag.value == tags_dict[tag.key]

    def test_adding_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)

        tags = [
            ResourceTag.objects.create(
                tenant_id=tenant_id,
                key="env",
                value="test",
            ),
        ]
        before_count = len(resource.tags.filter(tenant_id=tenant_id))

        resource.upsert_or_delete_tags(tags)

        assert before_count + 1 == len(resource.tags.filter(tenant_id=tenant_id))

        tags_dict = resource.get_tags(tenant_id=tenant_id)

        assert "env" in tags_dict
        assert tags_dict["env"] == "test"

    def test_adding_duplicate_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)

        tags = resource.tags.filter(tenant_id=tenant_id)

        before_count = len(resource.tags.filter(tenant_id=tenant_id))

        resource.upsert_or_delete_tags(tags)

        # should be the same number of tags
        assert before_count == len(resource.tags.filter(tenant_id=tenant_id))

    def test_add_tags_none(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)
        resource.upsert_or_delete_tags(None)

        assert len(resource.tags.filter(tenant_id=tenant_id)) == 0
        assert resource.get_tags(tenant_id=tenant_id) == {}

    def test_clear_tags(self, resources_fixture):
        resource, *_ = resources_fixture
        tenant_id = str(resource.tenant_id)
        resource.clear_tags()

        assert len(resource.tags.filter(tenant_id=tenant_id)) == 0
        assert resource.get_tags(tenant_id=tenant_id) == {}


# @pytest.mark.django_db
# class TestFindingModel:
#     def test_add_finding_with_long_uid(
#         self, providers_fixture, scans_fixture, resources_fixture
#     ):
#         provider, *_ = providers_fixture
#         tenant_id = provider.tenant_id

#         long_uid = "1" * 500
#         _ = Finding.objects.create(
#             tenant_id=tenant_id,
#             uid=long_uid,
#             delta=Finding.DeltaChoices.NEW,
#             check_metadata={},
#             status=StatusChoices.PASS,
#             status_extended="",
#             severity="high",
#             impact="high",
#             raw_result={},
#             check_id="test_check",
#             scan=scans_fixture[0],
#             first_seen_at=None,
#             muted=False,
#             compliance={},
#         )
#         assert Finding.objects.filter(uid=long_uid).exists()


@pytest.mark.django_db
class TestSAMLConfigurationsModel:
    def test_creates_valid_configuration(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant A")
        config = SAMLConfigurations.objects.using(MainRouter.admin_db).create(
            email_domain="ssoexample.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant,
        )

        assert config.email_domain == "ssoexample.com"
        assert SAMLDomainIndex.objects.filter(email_domain="ssoexample.com").exists()
        assert SocialApp.objects.filter(client_id="ssoexample.com").exists()

    def test_email_domain_with_at_symbol_fails(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant B")
        config = SAMLConfigurations(
            email_domain="invalid@domain.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.clean()

        errors = exc_info.value.message_dict
        assert "email_domain" in errors
        assert "Domain must not contain @" in errors["email_domain"][0]

    def test_duplicate_email_domain_fails(self):
        tenant1 = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant C1")
        tenant2 = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant C2")

        SAMLConfigurations.objects.using(MainRouter.admin_db).create(
            email_domain="duplicate.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant1,
        )

        config = SAMLConfigurations(
            email_domain="duplicate.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant2,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.clean()

        errors = exc_info.value.message_dict
        assert "tenant" in errors
        assert "There is a problem with your email domain." in errors["tenant"][0]

    def test_duplicate_tenant_config_fails(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant D")

        SAMLConfigurations.objects.using(MainRouter.admin_db).create(
            email_domain="unique1.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant,
        )

        config = SAMLConfigurations(
            email_domain="unique2.com",
            metadata_xml=VALID_METADATA,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.clean()

        errors = exc_info.value.message_dict
        assert "tenant" in errors
        assert (
            "A SAML configuration already exists for this tenant."
            in errors["tenant"][0]
        )

    def test_invalid_metadata_xml_fails(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant E")
        config = SAMLConfigurations(
            email_domain="brokenxml.com",
            metadata_xml="<bad<xml>",
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "Invalid XML" in errors["metadata_xml"][0]
        assert "not well-formed" in errors["metadata_xml"][0]

    def test_metadata_missing_sso_fails(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant F")
        xml = """<md:EntityDescriptor entityID="x" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:IDPSSODescriptor></md:IDPSSODescriptor>
                </md:EntityDescriptor>"""
        config = SAMLConfigurations(
            email_domain="nosso.com",
            metadata_xml=xml,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "Missing SingleSignOnService" in errors["metadata_xml"][0]

    def test_metadata_missing_certificate_fails(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant G")
        xml = """<md:EntityDescriptor entityID="x" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                    <md:IDPSSODescriptor>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso"/>
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>"""
        config = SAMLConfigurations(
            email_domain="nocert.com",
            metadata_xml=xml,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "X509Certificate" in errors["metadata_xml"][0]

    def test_updating_email_domain_deletes_old_domain_index(self):
        tenant = Tenant.objects.using(MainRouter.admin_db).create(name="Tenant Z")

        config = SAMLConfigurations.objects.using(MainRouter.admin_db).create(
            email_domain="original.com",
            metadata_xml="""<?xml version='1.0' encoding='UTF-8'?>
        <md:EntityDescriptor entityID='TEST' xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>
        <md:IDPSSODescriptor WantAuthnRequestsSigned='false' protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
            <md:KeyDescriptor use='signing'>
            <ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>
                <ds:X509Data>
                <ds:X509Certificate>TEST2</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
            <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://TEST/sso/saml'/>
            <md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://TEST/sso/saml'/>
        </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        """,
            tenant=tenant,
        )

        assert SAMLDomainIndex.objects.filter(email_domain="original.com").exists()

        config.email_domain = "updated.com"
        config.save()

        assert not SAMLDomainIndex.objects.filter(email_domain="original.com").exists()
        assert SAMLDomainIndex.objects.filter(
            email_domain="updated.com", tenant=tenant
        ).exists()
