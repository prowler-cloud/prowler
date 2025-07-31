import pytest
from allauth.socialaccount.models import SocialApp
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

from api.db_router import MainRouter
from api.models import (
    Resource,
    ResourceTag,
    SAMLConfiguration,
    SAMLDomainIndex,
    APIKey,
    Tenant,
    Role,
)


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
class TestSAMLConfigurationModel:
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

    def test_creates_valid_configuration(self, tenants_fixture):
        tenant = tenants_fixture[0]
        config = SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain="ssoexample.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant,
        )

        assert config.email_domain == "ssoexample.com"
        assert SocialApp.objects.filter(client_id="ssoexample.com").exists()

    def test_email_domain_with_at_symbol_fails(self, tenants_fixture):
        tenant = tenants_fixture[0]
        config = SAMLConfiguration(
            email_domain="invalid@domain.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.clean()

        errors = exc_info.value.message_dict
        assert "email_domain" in errors
        assert "Domain must not contain @" in errors["email_domain"][0]

    def test_duplicate_email_domain_fails(self, tenants_fixture):
        tenant1, tenant2, *_ = tenants_fixture

        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain="duplicate.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant1,
        )

        config = SAMLConfiguration(
            email_domain="duplicate.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant2,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.clean()

        errors = exc_info.value.message_dict
        assert "tenant" in errors
        assert "There is a problem with your email domain." in errors["tenant"][0]

    def test_duplicate_tenant_config_fails(self, tenants_fixture):
        tenant = tenants_fixture[0]

        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain="unique1.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant,
        )

        config = SAMLConfiguration(
            email_domain="unique2.com",
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
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

    def test_invalid_metadata_xml_fails(self, tenants_fixture):
        tenant = tenants_fixture[0]
        config = SAMLConfiguration(
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

    def test_metadata_missing_sso_fails(self, tenants_fixture):
        tenant = tenants_fixture[0]
        xml = """<md:EntityDescriptor entityID="x" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                <md:IDPSSODescriptor></md:IDPSSODescriptor>
                </md:EntityDescriptor>"""
        config = SAMLConfiguration(
            email_domain="nosso.com",
            metadata_xml=xml,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "Missing SingleSignOnService" in errors["metadata_xml"][0]

    def test_metadata_missing_certificate_fails(self, tenants_fixture):
        tenant = tenants_fixture[0]
        xml = """<md:EntityDescriptor entityID="x" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
                    <md:IDPSSODescriptor>
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso"/>
                    </md:IDPSSODescriptor>
                </md:EntityDescriptor>"""
        config = SAMLConfiguration(
            email_domain="nocert.com",
            metadata_xml=xml,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "X509Certificate" in errors["metadata_xml"][0]

    def test_deletes_saml_configuration_and_related_objects(self, tenants_fixture):
        tenant = tenants_fixture[0]
        email_domain = "deleteme.com"

        # Create the configuration
        config = SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain=email_domain,
            metadata_xml=TestSAMLConfigurationModel.VALID_METADATA,
            tenant=tenant,
        )

        # Verify that the SocialApp and SAMLDomainIndex exist
        assert SocialApp.objects.filter(client_id=email_domain).exists()
        assert (
            SAMLDomainIndex.objects.using(MainRouter.admin_db)
            .filter(email_domain=email_domain)
            .exists()
        )

        # Delete the configuration
        config.delete()

        # Verify that the configuration and its related objects are deleted
        assert (
            not SAMLConfiguration.objects.using(MainRouter.admin_db)
            .filter(pk=config.pk)
            .exists()
        )
        assert not SocialApp.objects.filter(client_id=email_domain).exists()
        assert (
            not SAMLDomainIndex.objects.using(MainRouter.admin_db)
            .filter(email_domain=email_domain)
            .exists()
        )

    def test_duplicate_entity_id_fails_on_creation(self, tenants_fixture):
        tenant1, tenant2, *_ = tenants_fixture
        SAMLConfiguration.objects.using(MainRouter.admin_db).create(
            email_domain="first.com",
            metadata_xml=self.VALID_METADATA,
            tenant=tenant1,
        )

        config = SAMLConfiguration(
            email_domain="second.com",
            metadata_xml=self.VALID_METADATA,
            tenant=tenant2,
        )

        with pytest.raises(ValidationError) as exc_info:
            config.save()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors
        assert "There is a problem with your metadata." in errors["metadata_xml"][0]


@pytest.mark.django_db
class TestAPIKeyModel:
    @pytest.fixture
    def tenant(self):
        """Create a test tenant for API key tests."""
        return Tenant.objects.create(name="Test Tenant")

    @pytest.fixture
    def role(self, tenant):
        """Create a test role for API key tests."""
        return Role.objects.create(
            name="Test Role",
            tenant=tenant,
            manage_scans=True,  # Allow basic scan permissions for testing
        )

    def test_generate_key_format(self):
        """Test that generate_key produces correctly formatted keys."""
        key = APIKey.generate_key()

        # Should be in format pk_XXXXXXXX.YYYYYYYY
        assert key.startswith("pk_")
        parts = key.split(".")
        assert len(parts) == 2

        # First part should be pk_ + 8 characters
        prefix_part = parts[0]
        assert len(prefix_part) == 11  # "pk_" + 8 chars
        assert prefix_part.startswith("pk_")

        # Second part should be 32 characters
        random_part = parts[1]
        assert len(random_part) == 32

    def test_generate_key_uniqueness(self):
        """Test that generate_key produces unique keys."""
        keys = {APIKey.generate_key() for _ in range(100)}
        # All 100 keys should be unique
        assert len(keys) == 100

    def test_extract_prefix_valid_key(self):
        """Test extracting prefix from valid API key."""
        key = "pk_abcd1234.xyz789abcdef123456789012345678"
        prefix = APIKey.extract_prefix(key)
        assert prefix == "abcd1234"

    def test_extract_prefix_invalid_format_no_dot(self):
        """Test extracting prefix from key without dot separator."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKey.extract_prefix("pk_abcd1234xyz789")

    def test_extract_prefix_invalid_format_no_pk_prefix(self):
        """Test extracting prefix from key without pk_ prefix."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKey.extract_prefix("abcd1234.xyz789")

    def test_extract_prefix_invalid_format_too_many_dots(self):
        """Test extracting prefix from key with too many dots."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKey.extract_prefix("pk_abcd1234.xyz789.extra")

    def test_extract_prefix_invalid_format_empty_string(self):
        """Test extracting prefix from empty string."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKey.extract_prefix("")

    def test_extract_prefix_invalid_format_none(self):
        """Test extracting prefix from None."""
        with pytest.raises(ValueError, match="Invalid API key format"):
            APIKey.extract_prefix(None)

    def test_hash_key(self):
        """Test that hash_key produces secure hashes."""
        key = "pk_test1234.abcdef123456789012345678901234"
        key_hash = APIKey.hash_key(key)

        # Hash should not be the same as the original key
        assert key_hash != key
        # Hash should be a non-empty string
        assert isinstance(key_hash, str)
        assert len(key_hash) > 0
        # Django password hashes typically start with algorithm identifier
        assert key_hash.startswith(("pbkdf2_", "argon2", "bcrypt"))

    def test_hash_key_same_input_different_hashes(self):
        """Test that hashing the same key twice produces different hashes (due to salt)."""
        key = "pk_test1234.abcdef123456789012345678901234"
        hash1 = APIKey.hash_key(key)
        hash2 = APIKey.hash_key(key)

        # Hashes should be different due to random salt
        assert hash1 != hash2

    def test_verify_key_correct_key(self):
        """Test verifying a correct API key against its hash."""
        key = "pk_test1234.abcdef123456789012345678901234"
        key_hash = APIKey.hash_key(key)

        assert APIKey.verify_key(key, key_hash) is True

    def test_verify_key_incorrect_key(self):
        """Test verifying an incorrect API key against a hash."""
        correct_key = "pk_test1234.abcdef123456789012345678901234"
        incorrect_key = "pk_wrong123.abcdef123456789012345678901234"
        key_hash = APIKey.hash_key(correct_key)

        assert APIKey.verify_key(incorrect_key, key_hash) is False

    def test_verify_key_empty_key(self):
        """Test verifying an empty key."""
        key = "pk_test1234.abcdef123456789012345678901234"
        key_hash = APIKey.hash_key(key)

        assert APIKey.verify_key("", key_hash) is False

    def test_is_valid_active_key(self, tenant, role):
        """Test that an active, non-expired key is valid."""
        api_key = APIKey.objects.create(
            name="Test Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey1",
            expiry_date=None,  # No expiration
            revoked=False,  # Not revoked
        )

        assert api_key.is_active() is True

    def test_is_valid_expired_key(self, tenant, role):
        """Test that an expired key is invalid."""
        past_time = timezone.now() - timedelta(hours=1)
        api_key = APIKey.objects.create(
            name="Expired Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey2",
            expiry_date=past_time,
            revoked=False,
        )

        assert api_key.is_active() is False

    def test_is_valid_future_expiry_key(self, tenant, role):
        """Test that a key with future expiry is valid."""
        future_time = timezone.now() + timedelta(hours=1)
        api_key = APIKey.objects.create(
            name="Future Expiry Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey3",
            expiry_date=future_time,
            revoked=False,
        )

        assert api_key.is_active() is True

    def test_is_valid_revoked_key(self, tenant, role):
        """Test that a revoked key is invalid."""
        api_key = APIKey.objects.create(
            name="Revoked Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey4",
            expiry_date=None,
            revoked=True,
        )

        assert api_key.is_active() is False

    def test_is_valid_revoked_and_expired_key(self, tenant, role):
        """Test that a key that is both revoked and expired is invalid."""
        past_time = timezone.now() - timedelta(hours=1)
        api_key = APIKey.objects.create(
            name="Revoked and Expired Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey5",
            expiry_date=past_time,
            revoked=True,
        )

        assert api_key.is_active() is False

    def test_revoke_key(self, tenant, role):
        """Test revoking an API key."""
        api_key = APIKey.objects.create(
            name="Key to Revoke",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey6",
            expiry_date=None,
            revoked=False,
        )

        # Initially active
        assert api_key.is_active() is True
        assert api_key.revoked is False

        # Revoke the key
        api_key.revoke()

        # Should now be inactive and revoked
        assert api_key.is_active() is False
        assert api_key.revoked is True

    def test_revoke_key_idempotent(self, tenant, role):
        """Test that revoking an already revoked key is safe."""
        api_key = APIKey.objects.create(
            name="Key to Double Revoke",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey7",
            expiry_date=None,
            revoked=False,
        )

        # Revoke twice
        api_key.revoke()
        first_revoked_status = api_key.revoked

        api_key.revoke()
        second_revoked_status = api_key.revoked

        # Should still be inactive and revoked
        assert api_key.is_active() is False
        assert first_revoked_status is True
        assert second_revoked_status is True

    def test_save_allows_empty_prefix(self, tenant, role):
        """Test that saving an API key allows empty prefix (will be generated)."""
        api_key = APIKey(
            name="Key without prefix",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="",  # Empty prefix is allowed
        )

        # Should save successfully (the library may generate a prefix)
        api_key.save()
        assert api_key.id is not None

    def test_api_key_string_representation(self, tenant, role):
        """Test the string representation of an API key."""
        api_key = APIKey.objects.create(
            name="Test API Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash",
            prefix="testkey8",
        )

        str_repr = str(api_key)
        assert str_repr == "API Key: Test API Key"

    def test_api_key_prefix_uniqueness_constraint(self, tenant, role):
        """Test that API key prefixes should be unique at the database level."""
        # Create first API key
        APIKey.objects.create(
            name="First Key",
            tenant_id=tenant.id,
            role=role,
            hashed_key="dummy_hash1",
            prefix="testkey9",
        )

        # Try to create second API key with same prefix - should fail due to unique constraint
        with pytest.raises(Exception):  # IntegrityError for unique constraint violation
            APIKey.objects.create(
                name="Second Key",
                tenant_id=tenant.id,
                role=role,
                hashed_key="dummy_hash2",
                prefix="testkey9",
            )

    def test_generated_key_works_end_to_end(self, tenant, role):
        """Test that a generated key can be hashed, stored, and verified."""
        # Generate a key
        raw_key = APIKey.generate_key()

        # Extract prefix and hash
        prefix = APIKey.extract_prefix(raw_key)
        key_hash = APIKey.hash_key(raw_key)

        # Create API key in database
        api_key = APIKey.objects.create(
            name="Generated Key Test",
            tenant_id=tenant.id,
            role=role,
            hashed_key=key_hash,
            prefix=prefix,
        )

        # Verify the key works
        assert APIKey.verify_key(raw_key, api_key.hashed_key) is True
        assert api_key.is_active() is True

        # Verify prefix extraction matches
        assert APIKey.extract_prefix(raw_key) == api_key.prefix
