import importlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from allauth.socialaccount.models import SocialApp
from api.db_router import MainRouter
from api.models import (
    Integration,
    JiraIssue,
    ProviderComplianceScore,
    Resource,
    ResourceTag,
    SAMLConfiguration,
    SAMLDomainIndex,
    StateChoices,
    StatusChoices,
    TenantComplianceSummary,
)
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.utils import timezone


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


@pytest.mark.django_db
class TestJiraIssueModel:
    @staticmethod
    def _common(jira_integration, provider, finding):
        return {
            "tenant_id": jira_integration.tenant_id,
            "integration": jira_integration,
            "provider": provider,
            "finding_uid": finding.uid,
            "finding_id": finding.id,
        }

    @staticmethod
    def _link(issue_number):
        return {
            "issue_id": str(10000 + issue_number),
            "issue_key": f"TEST-{issue_number}",
            "issue_url": f"https://test.atlassian.net/browse/TEST-{issue_number}",
            "project_key": "TEST",
            "issue_type": "Task",
        }

    def test_create_jira_issue(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        finding = findings_fixture[0]
        issue = JiraIssue.objects.create(
            **self._common(jira_integration_fixture, aws_provider, finding),
            **self._link(1),
        )
        assert issue.is_linked
        assert not issue.is_done
        assert issue.issue_status_category is None
        assert issue.attempt_state == JiraIssue.AttemptStateChoices.IDLE

    def test_idle_row_is_not_linked(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        finding = findings_fixture[0]
        issue = JiraIssue.objects.create(
            **self._common(jira_integration_fixture, aws_provider, finding),
        )
        assert not issue.is_linked
        assert issue.issue_id is None
        assert issue.issue_key is None
        assert issue.issue_url is None

    def test_unique_per_integration_provider_and_finding_uid(
        self, jira_integration_fixture, aws_provider_pair, findings_fixture
    ):
        provider, provider2 = aws_provider_pair
        finding = findings_fixture[0]
        common = {
            "tenant_id": jira_integration_fixture.tenant_id,
            "integration": jira_integration_fixture,
            "finding_uid": finding.uid,
            "finding_id": finding.id,
        }
        JiraIssue.objects.create(provider=provider, **common)
        # Same finding uid on another provider is a different finding
        JiraIssue.objects.create(provider=provider2, **common)
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(provider=provider, **common)

    def test_identity_and_issue_id_are_independent_across_integrations(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        finding = findings_fixture[0]
        other_integration = Integration.objects.create(
            tenant_id=jira_integration_fixture.tenant_id,
            enabled=True,
            connected=True,
            integration_type=Integration.IntegrationChoices.JIRA,
            configuration={"domain": "other-site"},
            credentials={
                "domain": "other-site",
                "user_mail": "other@example.com",
                "api_token": "token",
            },
        )
        JiraIssue.objects.create(
            **self._common(jira_integration_fixture, aws_provider, finding),
            **self._link(1),
        )

        other_issue = JiraIssue.objects.create(
            **self._common(other_integration, aws_provider, finding),
            **self._link(1),
        )

        assert other_issue.integration_id == other_integration.id
        assert JiraIssue.objects.filter(finding_uid=finding.uid).count() == 2

    def test_delivery_attempt_token_is_unique(
        self, jira_integration_fixture, aws_provider_pair, findings_fixture
    ):
        provider, provider2 = aws_provider_pair
        finding1, finding2 = findings_fixture
        token = uuid4()
        attempt = {
            "attempt_state": JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            "delivery_attempt_token": token,
            "attempt_operation": JiraIssue.AttemptOperationChoices.INITIAL,
            "attempt_project_key": "TEST",
            "attempt_issue_type": "Task",
        }
        JiraIssue.objects.create(
            **self._common(jira_integration_fixture, provider, finding1),
            **attempt,
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(jira_integration_fixture, provider2, finding2),
                **attempt,
            )

    def test_issue_identity_is_unique_per_integration(
        self, jira_integration_fixture, aws_provider_pair, findings_fixture
    ):
        provider, provider2 = aws_provider_pair
        finding1, finding2 = findings_fixture
        JiraIssue.objects.create(
            **self._common(jira_integration_fixture, provider, finding1),
            **self._link(1),
        )
        duplicate_link = self._link(2) | {"issue_id": "10001"}
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(jira_integration_fixture, provider2, finding2),
                **duplicate_link,
            )

    def test_link_fields_are_all_populated_or_all_null(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                issue_id="10001",
            )

    def test_creating_attempt_requires_complete_claim_and_destination(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        common = self._common(
            jira_integration_fixture, aws_provider, findings_fixture[0]
        )
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **common,
                attempt_state=JiraIssue.AttemptStateChoices.CREATING,
                delivery_attempt_token=uuid4(),
                attempt_operation=JiraIssue.AttemptOperationChoices.INITIAL,
                attempt_project_key="TEST",
                attempt_issue_type="Task",
            )

        issue = JiraIssue.objects.create(
            **common,
            attempt_state=JiraIssue.AttemptStateChoices.CREATING,
            claim_token="task-id",
            claim_expires_at=timezone.now() + timedelta(minutes=15),
            delivery_attempt_token=uuid4(),
            attempt_operation=JiraIssue.AttemptOperationChoices.INITIAL,
            attempt_project_key="TEST",
            attempt_issue_type="Task",
        )
        assert issue.claim_token == "task-id"

    @pytest.mark.parametrize("missing_field", ["claim_token", "claim_expires_at"])
    def test_claim_fields_are_all_populated_or_all_null(
        self,
        jira_integration_fixture,
        aws_provider,
        findings_fixture,
        missing_field,
    ):
        claim = {
            "claim_token": "task-id",
            "claim_expires_at": timezone.now() + timedelta(minutes=15),
        }
        claim.pop(missing_field)
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                **claim,
            )

    def test_claim_requires_creating_state(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                attempt_state=JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
                claim_token="task-id",
                claim_expires_at=timezone.now() + timedelta(minutes=15),
                delivery_attempt_token=uuid4(),
                attempt_operation=JiraIssue.AttemptOperationChoices.INITIAL,
                attempt_project_key="TEST",
                attempt_issue_type="Task",
            )

    @pytest.mark.parametrize(
        ("field", "value"),
        [("attempt_state", "invalid"), ("attempt_operation", "invalid")],
    )
    def test_attempt_enums_are_enforced_by_the_database(
        self,
        jira_integration_fixture,
        aws_provider,
        findings_fixture,
        field,
        value,
    ):
        values = {
            "attempt_state": JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            "delivery_attempt_token": uuid4(),
            "attempt_operation": JiraIssue.AttemptOperationChoices.INITIAL,
            "attempt_project_key": "TEST",
            "attempt_issue_type": "Task",
            field: value,
        }
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                **values,
            )

    @pytest.mark.parametrize(
        "missing_field",
        [
            "delivery_attempt_token",
            "attempt_operation",
            "attempt_project_key",
            "attempt_issue_type",
        ],
    )
    def test_non_idle_attempt_requires_delivery_fields(
        self,
        jira_integration_fixture,
        aws_provider,
        findings_fixture,
        missing_field,
    ):
        attempt = {
            "attempt_state": JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            "delivery_attempt_token": uuid4(),
            "attempt_operation": JiraIssue.AttemptOperationChoices.INITIAL,
            "attempt_project_key": "TEST",
            "attempt_issue_type": "Task",
        }
        attempt.pop(missing_field)
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                **attempt,
            )

    def test_replacement_attempt_requires_current_link(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                attempt_state=JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
                delivery_attempt_token=uuid4(),
                attempt_operation=JiraIssue.AttemptOperationChoices.REPLACEMENT,
                attempt_project_key="TEST",
                attempt_issue_type="Task",
            )

    def test_valid_replacement_retains_current_link(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        issue = JiraIssue.objects.create(
            **self._common(jira_integration_fixture, aws_provider, findings_fixture[0]),
            **self._link(1),
            attempt_state=JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            delivery_attempt_token=uuid4(),
            attempt_operation=JiraIssue.AttemptOperationChoices.REPLACEMENT,
            attempt_project_key="TEST",
            attempt_issue_type="Task",
        )

        assert issue.issue_id == "10001"
        assert issue.attempt_operation == JiraIssue.AttemptOperationChoices.REPLACEMENT

    def test_reconciliation_time_requires_uncertain_state(
        self, jira_integration_fixture, aws_provider, findings_fixture
    ):
        with pytest.raises(IntegrityError), transaction.atomic():
            JiraIssue.objects.create(
                **self._common(
                    jira_integration_fixture, aws_provider, findings_fixture[0]
                ),
                next_reconcile_at=timezone.now(),
            )


@pytest.mark.django_db
class TestJiraMigrations:
    def test_jira_ledger_constraints_indexes_and_rls_policies_exist(self):
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(
                cursor, JiraIssue._meta.db_table
            )
            cursor.execute(
                "SELECT cmd FROM pg_policies WHERE tablename = %s",
                [JiraIssue._meta.db_table],
            )
            policy_commands = {row[0] for row in cursor.fetchall()}

        assert {
            "unique_jira_issue_per_finding",
            "unique_jira_delivery_attempt",
            "unique_jira_issue_identity",
            "jira_issue_link_all_or_none",
            "jira_issue_claim_all_or_none",
            "jira_issue_valid_attempt_state",
            "jira_issue_valid_operation",
            "jira_issue_attempt_fields",
            "jira_issue_creating_has_claim",
            "jira_issue_claim_only_creating",
            "jira_issue_replacement_has_link",
            "jira_issue_reconcile_uncertain",
            "ji_ui_lookup_idx",
            "ji_stale_claim_idx",
            "ji_reconcile_due_idx",
        } <= constraints.keys()
        assert policy_commands == {"SELECT", "INSERT", "UPDATE", "DELETE"}

    def test_jira_site_data_migration_normalizes_configuration_and_credentials(self):
        migration = importlib.import_module("api.migrations.0100_jira_site_identity")
        cipher = Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())
        integration = SimpleNamespace(
            id=uuid4(),
            tenant_id=uuid4(),
            configuration={"projects": {"TEST": "Test"}},
            _credentials=cipher.encrypt(
                json.dumps(
                    {
                        "domain": " Example-Site ",
                        "user_mail": "jira@example.com",
                        "api_token": "token",
                    }
                ).encode()
            ),
        )

        class FakeManager:
            def __init__(self):
                self.bulk_update_args = None

            def using(self, _alias):
                return self

            def filter(self, **_kwargs):
                return self

            def only(self, *_fields):
                return [integration]

            def bulk_update(self, *args, **kwargs):
                self.bulk_update_args = (args, kwargs)

        manager = FakeManager()
        apps = SimpleNamespace(
            get_model=lambda *_args: SimpleNamespace(objects=manager)
        )

        migration.normalize_jira_domains(apps, None)

        credentials = json.loads(cipher.decrypt(integration._credentials).decode())
        assert integration.configuration == {
            "projects": {"TEST": "Test"},
            "domain": "example-site",
        }
        assert credentials["domain"] == "example-site"
        assert manager.bulk_update_args[0][0] == [integration]

    def test_jira_site_data_migration_rejects_case_insensitive_duplicates(self):
        migration = importlib.import_module("api.migrations.0100_jira_site_identity")
        cipher = Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())
        tenant_id = uuid4()
        integrations = [
            SimpleNamespace(
                id=uuid4(),
                tenant_id=tenant_id,
                configuration={},
                _credentials=cipher.encrypt(json.dumps({"domain": domain}).encode()),
            )
            for domain in ("Example-Site", "example-site")
        ]

        class FakeManager:
            def using(self, _alias):
                return self

            def filter(self, **_kwargs):
                return self

            def only(self, *_fields):
                return integrations

            def bulk_update(self, *_args, **_kwargs):
                raise AssertionError("duplicates must fail before writing")

        apps = SimpleNamespace(
            get_model=lambda *_args: SimpleNamespace(objects=FakeManager())
        )

        with pytest.raises(RuntimeError, match="Duplicate Jira integrations"):
            migration.normalize_jira_domains(apps, None)

    def test_jira_site_constraint_is_case_insensitive_per_tenant(self, tenants_fixture):
        tenant, other_tenant, *_ = tenants_fixture
        attributes = {
            "enabled": True,
            "connected": True,
            "integration_type": Integration.IntegrationChoices.JIRA,
            "configuration": {"domain": "Example-Site"},
            "credentials": {
                "domain": "Example-Site",
                "user_mail": "jira@example.com",
                "api_token": "token",
            },
        }
        Integration.objects.create(tenant=tenant, **attributes)

        with pytest.raises(IntegrityError), transaction.atomic():
            Integration.objects.create(
                tenant=tenant,
                **(
                    attributes
                    | {
                        "configuration": {"domain": "example-site"},
                        "credentials": attributes["credentials"]
                        | {"domain": "example-site"},
                    }
                ),
            )

        other = Integration.objects.create(
            tenant=other_tenant,
            **(
                attributes
                | {
                    "configuration": {"domain": "example-site"},
                    "credentials": attributes["credentials"]
                    | {"domain": "example-site"},
                }
            ),
        )
        assert other.tenant_id == other_tenant.id
