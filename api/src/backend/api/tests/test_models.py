from datetime import UTC, datetime, timedelta

import pytest
from allauth.socialaccount.models import SocialApp
from api.db_router import MainRouter
from api.models import (
    Provider,
    ProviderComplianceScore,
    Resource,
    ResourceTag,
    SAMLConfiguration,
    SAMLDomainIndex,
    Scan,
    StateChoices,
    StatusChoices,
    TenantComplianceSummary,
)
from django.core.exceptions import ValidationError
from django.db import IntegrityError


@pytest.mark.django_db
class TestResourceModel:
    def test_setting_tags(self, aws_provider):
        provider = aws_provider
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
#         self, aws_provider, scans_fixture, resources_fixture
#     ):
#         provider = aws_provider
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

    def test_xml_bomb_rejected(self, tenants_fixture):
        """
        Regression test: a 'billion laughs' XML bomb in the SAML metadata field
        must be rejected and not allowed to exhaust server memory / CPU.

        Before the fix, xml.etree.ElementTree was used directly, which does not
        protect against entity-expansion attacks.  The fix switches to defusedxml
        which raises an exception for any XML containing entity definitions.
        """
        tenant = tenants_fixture[0]
        xml_bomb = (
            "<?xml version='1.0'?>"
            "<!DOCTYPE bomb ["
            "  <!ENTITY a 'aaaaaaaaaa'>"
            "  <!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>"
            "  <!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'>"
            "  <!ENTITY d '&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;'>"
            "]>"
            "<md:EntityDescriptor entityID='&d;' "
            "xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'/>"
        )
        config = SAMLConfiguration(
            email_domain="xmlbomb.com",
            metadata_xml=xml_bomb,
            tenant=tenant,
        )

        with pytest.raises(ValidationError) as exc_info:
            config._parse_metadata()

        errors = exc_info.value.message_dict
        assert "metadata_xml" in errors

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
class TestProviderComplianceScoreModel:
    def test_create_provider_compliance_score(self, aws_provider, scans_fixture):
        provider = aws_provider
        scan = scans_fixture[0]
        scan.completed_at = datetime.now(UTC)
        scan.save()

        score = ProviderComplianceScore.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            scan=scan,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan.completed_at,
        )

        assert score.compliance_id == "aws_cis_2.0"
        assert score.requirement_id == "req_1"
        assert score.requirement_status == StatusChoices.PASS

    def test_unique_constraint_per_provider_compliance_requirement(
        self, aws_provider, scans_fixture
    ):
        provider = aws_provider
        scan = scans_fixture[0]
        scan.completed_at = datetime.now(UTC)
        scan.save()

        ProviderComplianceScore.objects.create(
            tenant_id=provider.tenant_id,
            provider=provider,
            scan=scan,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan.completed_at,
        )

        with pytest.raises(IntegrityError):
            ProviderComplianceScore.objects.create(
                tenant_id=provider.tenant_id,
                provider=provider,
                scan=scan,
                compliance_id="aws_cis_2.0",
                requirement_id="req_1",
                requirement_status=StatusChoices.FAIL,
                scan_completed_at=scan.completed_at,
            )

    def test_different_providers_same_requirement_allowed(
        self, aws_provider_pair, scans_fixture
    ):
        provider1, provider2 = aws_provider_pair
        scan1 = scans_fixture[0]
        scan1.completed_at = datetime.now(UTC)
        scan1.save()

        scan2 = scans_fixture[2]
        scan2.state = StateChoices.COMPLETED
        scan2.completed_at = datetime.now(UTC)
        scan2.save()

        score1 = ProviderComplianceScore.objects.create(
            tenant_id=provider1.tenant_id,
            provider=provider1,
            scan=scan1,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.PASS,
            scan_completed_at=scan1.completed_at,
        )

        score2 = ProviderComplianceScore.objects.create(
            tenant_id=provider2.tenant_id,
            provider=provider2,
            scan=scan2,
            compliance_id="aws_cis_2.0",
            requirement_id="req_1",
            requirement_status=StatusChoices.FAIL,
            scan_completed_at=scan2.completed_at,
        )

        assert score1.id != score2.id
        assert score1.requirement_status != score2.requirement_status


@pytest.mark.django_db
class TestTenantComplianceSummaryModel:
    def test_create_tenant_compliance_summary(self, tenants_fixture):
        tenant = tenants_fixture[0]

        summary = TenantComplianceSummary.objects.create(
            tenant_id=tenant.id,
            compliance_id="aws_cis_2.0",
            requirements_passed=5,
            requirements_failed=2,
            requirements_manual=1,
            total_requirements=8,
        )

        assert summary.compliance_id == "aws_cis_2.0"
        assert summary.requirements_passed == 5
        assert summary.requirements_failed == 2
        assert summary.requirements_manual == 1
        assert summary.total_requirements == 8
        assert summary.updated_at is not None

    def test_unique_constraint_per_tenant_compliance(self, tenants_fixture):
        tenant = tenants_fixture[0]

        TenantComplianceSummary.objects.create(
            tenant_id=tenant.id,
            compliance_id="aws_cis_2.0",
            requirements_passed=5,
            requirements_failed=2,
            requirements_manual=1,
            total_requirements=8,
        )

        with pytest.raises(IntegrityError):
            TenantComplianceSummary.objects.create(
                tenant_id=tenant.id,
                compliance_id="aws_cis_2.0",
                requirements_passed=3,
                requirements_failed=4,
                requirements_manual=1,
                total_requirements=8,
            )

    def test_different_tenants_same_compliance_allowed(self, tenants_fixture):
        tenant1, tenant2, *_ = tenants_fixture

        summary1 = TenantComplianceSummary.objects.create(
            tenant_id=tenant1.id,
            compliance_id="aws_cis_2.0",
            requirements_passed=5,
            requirements_failed=2,
            requirements_manual=1,
            total_requirements=8,
        )

        summary2 = TenantComplianceSummary.objects.create(
            tenant_id=tenant2.id,
            compliance_id="aws_cis_2.0",
            requirements_passed=3,
            requirements_failed=4,
            requirements_manual=1,
            total_requirements=8,
        )

        assert summary1.id != summary2.id
        assert summary1.requirements_passed != summary2.requirements_passed


def _latest_scan_fixture(tenant, provider, *, completed_at, inserted_at=None, **kwargs):
    scan = Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        trigger=kwargs.pop("trigger", Scan.TriggerChoices.MANUAL),
        state=kwargs.pop("state", StateChoices.COMPLETED),
        completed_at=completed_at,
        **kwargs,
    )
    if inserted_at is not None:
        # `inserted_at` is auto_now_add, so it has to be forced after the fact.
        Scan.all_objects.filter(pk=scan.pk).update(inserted_at=inserted_at)
        scan.refresh_from_db()
    return scan


@pytest.mark.django_db
class TestScanQuerySetOrdering:
    def test_completed_later_wins_over_inserted_later(
        self, tenants_fixture, aws_provider
    ):
        """The scan that FINISHED last is current, not the one that started last."""
        tenant, *_ = tenants_fixture
        now = datetime.now(UTC)

        finished_last = _latest_scan_fixture(
            tenant,
            aws_provider,
            inserted_at=now - timedelta(hours=3),
            completed_at=now,
        )
        _latest_scan_fixture(
            tenant,
            aws_provider,
            inserted_at=now - timedelta(hours=1),
            completed_at=now - timedelta(hours=1),
        )

        assert Scan.all_objects.filter(
            tenant_id=tenant.id
        ).latest_ids_per_provider() == [finished_last.id]

    def test_null_completed_at_provider_is_still_returned(
        self, tenants_fixture, aws_provider
    ):
        """NULLS LAST, not `completed_at__isnull=False`.

        Excluding NULL `completed_at` would drop the provider from every
        "latest" endpoint instead of falling back to `inserted_at`.
        """
        tenant, *_ = tenants_fixture
        only_scan = _latest_scan_fixture(tenant, aws_provider, completed_at=None)

        assert Scan.all_objects.filter(
            tenant_id=tenant.id
        ).latest_ids_per_provider() == [only_scan.id]

    def test_null_completed_at_never_outranks_a_finished_scan(
        self, tenants_fixture, aws_provider
    ):
        """Postgres sorts NULLs first under DESC; NULLS LAST is what fixes it."""
        tenant, *_ = tenants_fixture
        now = datetime.now(UTC)

        finished = _latest_scan_fixture(
            tenant,
            aws_provider,
            inserted_at=now - timedelta(hours=2),
            completed_at=now - timedelta(hours=2),
        )
        _latest_scan_fixture(
            tenant,
            aws_provider,
            inserted_at=now,
            completed_at=None,
        )

        assert Scan.all_objects.filter(
            tenant_id=tenant.id
        ).latest_ids_per_provider() == [finished.id]

    def test_id_breaks_an_exact_timestamp_tie_deterministically(
        self, tenants_fixture, aws_provider
    ):
        tenant, *_ = tenants_fixture
        now = datetime.now(UTC)

        scans = [
            _latest_scan_fixture(
                tenant, aws_provider, inserted_at=now, completed_at=now
            )
            for _ in range(3)
        ]
        expected = max(scan.id for scan in scans)

        picks = {
            Scan.all_objects.filter(tenant_id=tenant.id).latest_ids_per_provider()[0]
            for _ in range(5)
        }
        assert picks == {expected}


@pytest.mark.django_db
class TestScanQuerySetEligibility:
    def test_unfinished_scans_are_excluded(self, tenants_fixture, aws_provider):
        tenant, *_ = tenants_fixture
        _latest_scan_fixture(
            tenant,
            aws_provider,
            completed_at=None,
            state=StateChoices.EXECUTING,
        )
        assert (
            Scan.all_objects.filter(tenant_id=tenant.id).latest_ids_per_provider() == []
        )


@pytest.mark.django_db
class TestScanQuerySetManagerChoice:
    def test_active_manager_hides_soft_deleted_providers(
        self, tenants_fixture, aws_provider
    ):
        """`Scan.objects` drops soft-deleted providers, `all_objects` keeps them.

        The queryset must not decide this for the caller.
        """
        tenant, *_ = tenants_fixture
        scan = _latest_scan_fixture(
            tenant, aws_provider, completed_at=datetime.now(UTC)
        )

        Provider.all_objects.filter(pk=aws_provider.pk).update(is_deleted=True)

        assert Scan.all_objects.filter(
            tenant_id=tenant.id
        ).latest_ids_per_provider() == [scan.id]
        assert Scan.objects.filter(tenant_id=tenant.id).latest_ids_per_provider() == []


@pytest.mark.django_db
class TestScanQuerySetPerProviderScoping:
    def test_one_scan_per_provider(self, tenants_fixture, aws_provider_pair):
        tenant, *_ = tenants_fixture
        provider_one, provider_two = aws_provider_pair
        now = datetime.now(UTC)

        newest_one = _latest_scan_fixture(tenant, provider_one, completed_at=now)
        _latest_scan_fixture(tenant, provider_one, completed_at=now - timedelta(days=1))
        newest_two = _latest_scan_fixture(tenant, provider_two, completed_at=now)

        assert set(
            Scan.all_objects.filter(tenant_id=tenant.id).latest_ids_per_provider()
        ) == {newest_one.id, newest_two.id}

    def test_caller_filters_are_preserved(self, tenants_fixture, aws_provider_pair):
        tenant, *_ = tenants_fixture
        provider_one, provider_two = aws_provider_pair
        now = datetime.now(UTC)

        scan_one = _latest_scan_fixture(tenant, provider_one, completed_at=now)
        _latest_scan_fixture(tenant, provider_two, completed_at=now)

        assert Scan.all_objects.filter(
            tenant_id=tenant.id, provider__in=[provider_one]
        ).latest_ids_per_provider() == [scan_one.id]

    def test_latest_first_is_ordered_not_deduplicated(
        self, tenants_fixture, aws_provider
    ):
        tenant, *_ = tenants_fixture
        now = datetime.now(UTC)

        newest = _latest_scan_fixture(tenant, aws_provider, completed_at=now)
        older = _latest_scan_fixture(
            tenant, aws_provider, completed_at=now - timedelta(days=1)
        )

        ordered = list(
            Scan.all_objects.filter(
                tenant_id=tenant.id, provider_id=aws_provider.id
            ).latest_first()
        )
        assert [scan.id for scan in ordered] == [newest.id, older.id]

    def test_tenant_isolation(self, tenants_fixture, aws_provider):
        tenant, other_tenant, *_ = tenants_fixture
        _latest_scan_fixture(tenant, aws_provider, completed_at=datetime.now(UTC))

        assert (
            Scan.all_objects.filter(tenant_id=other_tenant.id).latest_ids_per_provider()
            == []
        )

    def test_empty_queryset_returns_empty_list(self, tenants_fixture):
        tenant, *_ = tenants_fixture
        assert (
            Scan.all_objects.filter(tenant_id=tenant.id).latest_ids_per_provider() == []
        )


@pytest.mark.django_db
class TestScanQuerySetPerProviderQuerysetShape:
    def test_returns_a_queryset_not_a_list(self, tenants_fixture, aws_provider):
        tenant, *_ = tenants_fixture
        _latest_scan_fixture(tenant, aws_provider, completed_at=datetime.now(UTC))

        qs = Scan.all_objects.filter(tenant_id=tenant.id).latest_per_provider()
        # Callers chain .values(...) / .values_list(...) onto this.
        assert qs.values_list("provider_id", flat=True).count() == 1


@pytest.mark.django_db
class TestScanQuerySetRelatedManager:
    def test_reverse_relation_exposes_the_methods(self, tenants_fixture, aws_provider):
        tenant, *_ = tenants_fixture
        now = datetime.now(UTC)

        newest = _latest_scan_fixture(tenant, aws_provider, completed_at=now)
        _latest_scan_fixture(tenant, aws_provider, completed_at=now - timedelta(days=1))

        assert aws_provider.scans.latest_first().first().id == newest.id
