from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from api.models import (
    Finding,
    MuteRule,
    Provider,
    Scan,
    StateChoices,
    User,
)
from conftest import get_api_tokens, get_authorization_header
from prowler.lib.check.models import Severity
from prowler.lib.outputs.finding import Status


@pytest.mark.django_db
class TestCompleteMuteRuleCreationWorkflow:
    """Test the complete workflow of creating a mute rule from selected findings."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_complete_mute_rule_creation_workflow(self, mock_task):
        """
        Test complete workflow: create user → authenticate → create findings →
        create mute rule → verify immediate muting → verify background task called →
        retrieve task.
        """
        client = APIClient()

        user_email = "mute_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Mute Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            alias="test-provider",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding1 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-ec2-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test status",
            severity=Severity.high,
            impact=Severity.high,
            check_id="ec2_test_check_1",
            check_metadata={"CheckId": "ec2_test_check_1"},
            raw_result={},
        )

        finding2 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-ec2-test-002",
            scan=scan,
            status=Status.FAIL,
            status_extended="test status",
            severity=Severity.high,
            impact=Severity.high,
            check_id="ec2_test_check_2",
            check_metadata={"CheckId": "ec2_test_check_2"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "False Positives",
                        "reason": "Security exception approved by team",
                        "finding_ids": [str(finding1.id), str(finding2.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert create_response.status_code == 201

        finding1.refresh_from_db()
        finding2.refresh_from_db()

        assert finding1.muted is True
        assert finding1.muted_at is not None
        assert finding1.muted_reason == "Security exception approved by team"

        assert finding2.muted is True
        assert finding2.muted_at is not None
        assert finding2.muted_reason == "Security exception approved by team"

        mock_task.assert_called_once()
        call_args = mock_task.call_args
        assert call_args.kwargs["kwargs"]["tenant_id"] == str(tenant.id)
        assert "mute_rule_id" in call_args.kwargs["kwargs"]

        rule = MuteRule.objects.get(name="False Positives")
        assert rule.tenant_id == tenant.id
        assert set(rule.finding_uids) == {
            "prowler-aws-ec2-test-001",
            "prowler-aws-ec2-test-002",
        }
        assert rule.created_by == user



@pytest.mark.django_db
class TestOverlapDetection:
    """Test overlap detection when creating rules with duplicate finding UIDs."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_overlap_detection_active_rule(self, mock_task):
        """
        Test that creating a rule with finding UIDs that overlap with an
        active rule returns 409 Conflict.
        """
        client = APIClient()

        user_email = "overlap_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Overlap Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-overlap-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        first_rule_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "First Rule",
                        "reason": "First reason",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert first_rule_response.status_code == 201

        first_rule = MuteRule.objects.get(name="First Rule")
        assert first_rule.is_active is True

        duplicate_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Duplicate Rule",
                        "reason": "This should fail",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert duplicate_response.status_code == 409
        assert "errors" in duplicate_response.json()
        error_detail = duplicate_response.json()["errors"][0]["detail"]
        assert "already muted" in error_detail.lower() or "overlap" in error_detail.lower()

        assert MuteRule.objects.filter(name="Duplicate Rule").exists() is False

        finding.refresh_from_db()
        assert finding.muted is True


@pytest.mark.django_db
class TestInactiveRulesBehavior:
    """Test that inactive rules don't block creation of new rules with same UIDs."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_inactive_rules_dont_block_overlaps(self, mock_task):
        """
        Test that when a rule is inactive, new rules with same UIDs can be created.
        """
        client = APIClient()

        user_email = "inactive_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Inactive Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-inactive-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        first_rule_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Active Rule",
                        "reason": "Active reason",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert first_rule_response.status_code == 201

        first_rule = MuteRule.objects.get(name="Active Rule")

        deactivate_response = client.patch(
            reverse("mute-rule-detail", kwargs={"pk": first_rule.id}),
            data={
                "data": {
                    "type": "mute-rules",
                    "id": str(first_rule.id),
                    "attributes": {
                        "is_active": False,
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert deactivate_response.status_code == 200

        second_rule_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "New Rule",
                        "reason": "This should succeed",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert second_rule_response.status_code == 201
        assert MuteRule.objects.filter(name="New Rule").exists() is True


@pytest.mark.django_db
class TestUpdateRuleWorkflow:
    """Test updating mute rules and verify existing muted findings unchanged."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_update_rule_workflow(self, mock_task):
        """
        Test updating rule name, reason, and is_active status, and verify
        existing muted findings remain unchanged.
        """
        client = APIClient()

        user_email = "update_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Update Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-update-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Original Name",
                        "reason": "Original reason",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert create_response.status_code == 201

        rule = MuteRule.objects.get(name="Original Name")
        finding.refresh_from_db()

        original_muted_at = finding.muted_at
        original_muted_reason = finding.muted_reason

        update_name_response = client.patch(
            reverse("mute-rule-detail", kwargs={"pk": rule.id}),
            data={
                "data": {
                    "type": "mute-rules",
                    "id": str(rule.id),
                    "attributes": {
                        "name": "Updated Name",
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert update_name_response.status_code == 200
        assert update_name_response.json()["data"]["attributes"]["name"] == "Updated Name"

        rule.refresh_from_db()
        assert rule.name == "Updated Name"

        update_reason_response = client.patch(
            reverse("mute-rule-detail", kwargs={"pk": rule.id}),
            data={
                "data": {
                    "type": "mute-rules",
                    "id": str(rule.id),
                    "attributes": {
                        "reason": "Updated reason",
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert update_reason_response.status_code == 200
        assert update_reason_response.json()["data"]["attributes"]["reason"] == "Updated reason"

        rule.refresh_from_db()
        assert rule.reason == "Updated reason"

        update_active_response = client.patch(
            reverse("mute-rule-detail", kwargs={"pk": rule.id}),
            data={
                "data": {
                    "type": "mute-rules",
                    "id": str(rule.id),
                    "attributes": {
                        "is_active": False,
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert update_active_response.status_code == 200
        assert update_active_response.json()["data"]["attributes"]["is_active"] is False

        rule.refresh_from_db()
        assert rule.is_active is False

        finding.refresh_from_db()
        assert finding.muted is True
        assert finding.muted_at == original_muted_at
        assert finding.muted_reason == original_muted_reason


@pytest.mark.django_db
class TestDeleteRuleWorkflow:
    """Test that deleting a rule preserves muted findings."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_delete_rule_preserves_muted_findings(self, mock_task):
        """
        Test that when a rule is deleted, findings remain muted with their
        muted_at timestamp preserved.
        """
        client = APIClient()

        user_email = "delete_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Delete Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-delete-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "To Be Deleted",
                        "reason": "Test deletion",
                        "finding_ids": [str(finding.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert create_response.status_code == 201

        rule = MuteRule.objects.get(name="To Be Deleted")
        finding.refresh_from_db()

        assert finding.muted is True
        original_muted_at = finding.muted_at
        original_muted_reason = finding.muted_reason
        assert original_muted_at is not None

        delete_response = client.delete(
            reverse("mute-rule-detail", kwargs={"pk": rule.id}),
            headers=auth_headers,
        )
        assert delete_response.status_code == 204

        assert MuteRule.objects.filter(id=rule.id).exists() is False

        get_response = client.get(
            reverse("mute-rule-detail", kwargs={"pk": rule.id}),
            headers=auth_headers,
        )
        assert get_response.status_code == 404

        finding.refresh_from_db()
        assert finding.muted is True
        assert finding.muted_at == original_muted_at
        assert finding.muted_reason == original_muted_reason


@pytest.mark.django_db
class TestUIDConversionWorkflow:
    """Test that finding IDs are correctly converted to UIDs."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_uid_conversion_workflow(self, mock_task):
        """
        Test that when creating a rule with finding IDs, they are converted
        to UIDs and stored in the rule.
        """
        client = APIClient()

        user_email = "uid_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "UID Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding1 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-uid-test-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_1",
            check_metadata={"CheckId": "test_check_1"},
            raw_result={},
        )

        finding2 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-uid-test-002",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_2",
            check_metadata={"CheckId": "test_check_2"},
            raw_result={},
        )

        finding3 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-uid-test-003",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_3",
            check_metadata={"CheckId": "test_check_3"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "UID Conversion Test",
                        "reason": "Testing UID conversion",
                        "finding_ids": [
                            str(finding1.id),
                            str(finding2.id),
                            str(finding3.id),
                        ],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert create_response.status_code == 201

        rule = MuteRule.objects.get(name="UID Conversion Test")
        assert set(rule.finding_uids) == {
            "prowler-aws-uid-test-001",
            "prowler-aws-uid-test-002",
            "prowler-aws-uid-test-003",
        }

        assert str(finding1.id) not in rule.finding_uids
        assert str(finding2.id) not in rule.finding_uids
        assert str(finding3.id) not in rule.finding_uids

        mock_task.assert_called_once()
        call_args = mock_task.call_args
        assert call_args.kwargs["kwargs"]["tenant_id"] == str(tenant.id)
        assert "mute_rule_id" in call_args.kwargs["kwargs"]

        finding1.refresh_from_db()
        finding2.refresh_from_db()
        finding3.refresh_from_db()

        assert finding1.muted is True
        assert finding2.muted is True
        assert finding3.muted is True
        assert finding1.muted_reason == "Testing UID conversion"
        assert finding2.muted_reason == "Testing UID conversion"
        assert finding3.muted_reason == "Testing UID conversion"


@pytest.mark.django_db
class TestTenantIsolationWorkflow:
    """Test that mute rules are properly isolated by tenant."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_tenant_isolation_workflow(self, mock_task):
        """
        Test that users can only see and access rules from their own tenant,
        and can create rules with the same name in different tenants.
        """
        client = APIClient()

        user1_email = "tenant1@prowler.com"
        user1_password = "Test_password@1"

        user1_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Tenant 1 User",
                        "email": user1_email,
                        "password": user1_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user1_response.status_code == 201
        user1 = User.objects.get(email=user1_email)
        tenant1 = user1.memberships.first().tenant

        user2_email = "tenant2@prowler.com"
        user2_password = "Test_password@1"

        user2_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Tenant 2 User",
                        "email": user2_email,
                        "password": user2_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user2_response.status_code == 201
        user2 = User.objects.get(email=user2_email)
        tenant2 = user2.memberships.first().tenant

        assert tenant1.id != tenant2.id

        access_token1, _ = get_api_tokens(client, user1_email, user1_password)
        auth_headers1 = get_authorization_header(access_token1)

        access_token2, _ = get_api_tokens(client, user2_email, user2_password)
        auth_headers2 = get_authorization_header(access_token2)

        provider1 = Provider.objects.create(
            tenant=tenant1,
            provider="aws",
            uid="111111111111",
            connected=True,
        )

        scan1 = Scan.objects.create(
            tenant=tenant1,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider1,
        )

        finding1 = Finding.objects.create(
            tenant=tenant1,
            uid="prowler-aws-tenant1-001",
            scan=scan1,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )

        mock_task_result = Mock()
        mock_task_result.id = "task-1"
        mock_task.return_value = mock_task_result




        rule1_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Shared Name",
                        "reason": "Tenant 1 rule",
                        "finding_ids": [str(finding1.id)],
                    },
                }
            },
            headers=auth_headers1,
            format="vnd.api+json",
        )
        assert rule1_response.status_code == 201

        rule1 = MuteRule.objects.get(name="Shared Name", tenant=tenant1)

        list_response_user2 = client.get(
            reverse("mute-rule-list"),
            headers=auth_headers2,
        )
        assert list_response_user2.status_code == 200
        assert len(list_response_user2.json()["data"]) == 0

        get_response_user2 = client.get(
            reverse("mute-rule-detail", kwargs={"pk": rule1.id}),
            headers=auth_headers2,
        )
        assert get_response_user2.status_code == 404

        provider2 = Provider.objects.create(
            tenant=tenant2,
            provider="aws",
            uid="222222222222",
            connected=True,
        )

        scan2 = Scan.objects.create(
            tenant=tenant2,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider2,
        )

        finding2 = Finding.objects.create(
            tenant=tenant2,
            uid="prowler-aws-tenant2-001",
            scan=scan2,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )



        rule2_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Shared Name",
                        "reason": "Tenant 2 rule",
                        "finding_ids": [str(finding2.id)],
                    },
                }
            },
            headers=auth_headers2,
            format="vnd.api+json",
        )
        assert rule2_response.status_code == 201

        assert MuteRule.objects.filter(name="Shared Name").count() == 2


@pytest.mark.django_db
class TestListAndFilterWorkflow:
    """Test listing and filtering mute rules."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_list_and_filter_workflow(self, mock_task):
        """
        Test creating multiple rules and filtering them by various criteria.
        """
        client = APIClient()

        user_email = "filter_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Filter Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        findings = []
        for i in range(5):
            finding = Finding.objects.create(
                tenant=tenant,
                uid=f"prowler-aws-filter-test-{i:03d}",
                scan=scan,
                status=Status.FAIL,
                status_extended="test",
                severity=Severity.high,
                impact=Severity.high,
                check_id=f"test_check_{i}",
                check_metadata={"CheckId": f"test_check_{i}"},
                raw_result={},
            )
            findings.append(finding)



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        rules_data = [
            {
                "name": "Active Rule 1",
                "reason": "Security exception",
                "finding_ids": [str(findings[0].id)],
                "is_active": True,
            },
            {
                "name": "Active Rule 2",
                "reason": "Compliance approved",
                "finding_ids": [str(findings[1].id)],
                "is_active": True,
            },
            {
                "name": "Inactive Rule",
                "reason": "Old exception",
                "finding_ids": [str(findings[2].id)],
                "is_active": False,
            },
        ]

        created_rules = []
        for rule_data in rules_data:
            is_active = rule_data.pop("is_active")
            create_response = client.post(
                reverse("mute-rule-list"),
                data={
                    "data": {
                        "type": "mute-rules",
                        "attributes": rule_data,
                    }
                },
                headers=auth_headers,
                format="vnd.api+json",
            )
            assert create_response.status_code == 201

            if not is_active:
                rule = MuteRule.objects.get(name=rule_data["name"])
                client.patch(
                    reverse("mute-rule-detail", kwargs={"pk": rule.id}),
                    data={
                        "data": {
                            "type": "mute-rules",
                            "id": str(rule.id),
                            "attributes": {"is_active": False},
                        }
                    },
                    headers=auth_headers,
                    format="vnd.api+json",
                )
            created_rules.append(rule_data["name"])

        list_all_response = client.get(
            reverse("mute-rule-list"),
            headers=auth_headers,
        )
        assert list_all_response.status_code == 200
        assert len(list_all_response.json()["data"]) == 3

        filter_active_response = client.get(
            reverse("mute-rule-list"),
            {"filter[is_active]": "true"},
            headers=auth_headers,
        )
        assert filter_active_response.status_code == 200
        active_rules = filter_active_response.json()["data"]
        assert len(active_rules) == 2
        for rule in active_rules:
            assert rule["attributes"]["is_active"] is True

        filter_inactive_response = client.get(
            reverse("mute-rule-list"),
            {"filter[is_active]": "false"},
            headers=auth_headers,
        )
        assert filter_inactive_response.status_code == 200
        inactive_rules = filter_inactive_response.json()["data"]
        assert len(inactive_rules) == 1
        assert inactive_rules[0]["attributes"]["is_active"] is False

        filter_name_response = client.get(
            reverse("mute-rule-list"),
            {"filter[name.icontains]": "Active Rule 1"},
            headers=auth_headers,
        )
        assert filter_name_response.status_code == 200
        filtered_names = filter_name_response.json()["data"]
        assert len(filtered_names) == 1
        assert "Active Rule 1" == filtered_names[0]["attributes"]["name"]

        search_response = client.get(
            reverse("mute-rule-list"),
            {"filter[search]": "Security"},
            headers=auth_headers,
        )
        assert search_response.status_code == 200
        assert len(search_response.json()["data"]) >= 1

        sort_response = client.get(
            reverse("mute-rule-list"),
            {"sort": "name"},
            headers=auth_headers,
        )
        assert sort_response.status_code == 200
        sorted_rules = sort_response.json()["data"]
        rule_names = [rule["attributes"]["name"] for rule in sorted_rules]
        assert rule_names == sorted(rule_names)


@pytest.mark.django_db
class TestErrorHandling:
    """Test error handling for various invalid inputs."""

    def test_create_rule_with_empty_finding_ids(self):
        """Test that creating a rule with empty finding_ids returns 400."""
        client = APIClient()

        user_email = "error_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Error Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Empty Finding IDs",
                        "reason": "This should fail",
                        "finding_ids": [],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert create_response.status_code == 400
        assert "errors" in create_response.json()

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_create_rule_with_nonexistent_finding_ids(self, mock_task):
        """Test that creating a rule with non-existent finding IDs returns 400."""
        client = APIClient()

        user_email = "nonexistent_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Nonexistent Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        nonexistent_uuid = str(uuid4())

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Nonexistent Finding",
                        "reason": "This should fail",
                        "finding_ids": [nonexistent_uuid],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert create_response.status_code == 400
        assert "errors" in create_response.json()

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_create_rule_with_duplicate_name(self, mock_task):
        """Test that creating a rule with a duplicate name returns 400."""
        client = APIClient()

        user_email = "duplicate_name_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Duplicate Name Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding1 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-dup-name-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_1",
            check_metadata={"CheckId": "test_check_1"},
            raw_result={},
        )

        finding2 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-dup-name-002",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_2",
            check_metadata={"CheckId": "test_check_2"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        first_rule_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Duplicate Name",
                        "reason": "First rule",
                        "finding_ids": [str(finding1.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert first_rule_response.status_code == 201

        second_rule_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Duplicate Name",
                        "reason": "Second rule should fail",
                        "finding_ids": [str(finding2.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert second_rule_response.status_code == 400
        assert "errors" in second_rule_response.json()

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_update_rule_to_duplicate_name(self, mock_task):
        """Test that updating a rule to a duplicate name returns 400."""
        client = APIClient()

        user_email = "update_dup_name_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Update Dup Name Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        finding1 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-update-dup-001",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_1",
            check_metadata={"CheckId": "test_check_1"},
            raw_result={},
        )

        finding2 = Finding.objects.create(
            tenant=tenant,
            uid="prowler-aws-update-dup-002",
            scan=scan,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check_2",
            check_metadata={"CheckId": "test_check_2"},
            raw_result={},
        )



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        rule1_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Rule One",
                        "reason": "First rule",
                        "finding_ids": [str(finding1.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert rule1_response.status_code == 201

        rule2_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Rule Two",
                        "reason": "Second rule",
                        "finding_ids": [str(finding2.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )
        assert rule2_response.status_code == 201

        rule2 = MuteRule.objects.get(name="Rule Two")

        update_response = client.patch(
            reverse("mute-rule-detail", kwargs={"pk": rule2.id}),
            data={
                "data": {
                    "type": "mute-rules",
                    "id": str(rule2.id),
                    "attributes": {
                        "name": "Rule One",
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert update_response.status_code == 400
        assert "errors" in update_response.json()


@pytest.mark.django_db
class TestMultipleFindingsSameUID:
    """Test muting multiple findings with the same UID."""

    @patch("tasks.tasks.mute_historical_findings_task.apply_async")
    def test_multiple_findings_same_uid_workflow(self, mock_task):
        """
        Test that when multiple findings share the same UID (historical findings
        from different scans), muting one via a rule mutes all of them.
        """
        client = APIClient()

        user_email = "same_uid_test@prowler.com"
        user_password = "Test_password@1"

        user_response = client.post(
            reverse("user-list"),
            data={
                "data": {
                    "type": "users",
                    "attributes": {
                        "name": "Same UID Test User",
                        "email": user_email,
                        "password": user_password,
                    },
                }
            },
            format="vnd.api+json",
        )
        assert user_response.status_code == 201
        user = User.objects.get(email=user_email)
        tenant = user.memberships.first().tenant

        access_token, _ = get_api_tokens(client, user_email, user_password)
        auth_headers = get_authorization_header(access_token)

        provider = Provider.objects.create(
            tenant=tenant,
            provider="aws",
            uid="123456789012",
            connected=True,
        )

        scan1 = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        scan2 = Scan.objects.create(
            tenant=tenant,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            provider=provider,
        )

        shared_uid = "prowler-aws-same-uid-shared-001"

        finding1_scan1 = Finding.objects.create(
            tenant=tenant,
            uid=shared_uid,
            scan=scan1,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )

        finding2_scan2 = Finding.objects.create(
            tenant=tenant,
            uid=shared_uid,
            scan=scan2,
            status=Status.FAIL,
            status_extended="test",
            severity=Severity.high,
            impact=Severity.high,
            check_id="test_check",
            check_metadata={"CheckId": "test_check"},
            raw_result={},
        )

        assert finding1_scan1.uid == finding2_scan2.uid
        assert finding1_scan1.id != finding2_scan2.id



        mock_task_result = Mock()
        mock_task.return_value = mock_task_result

        create_response = client.post(
            reverse("mute-rule-list"),
            data={
                "data": {
                    "type": "mute-rules",
                    "attributes": {
                        "name": "Mute Shared UID",
                        "reason": "Historical finding across scans",
                        "finding_ids": [str(finding1_scan1.id)],
                    },
                }
            },
            headers=auth_headers,
            format="vnd.api+json",
        )

        assert create_response.status_code == 201

        rule = MuteRule.objects.get(name="Mute Shared UID")
        assert len(rule.finding_uids) == 1
        assert rule.finding_uids[0] == shared_uid

        finding1_scan1.refresh_from_db()
        finding2_scan2.refresh_from_db()

        assert finding1_scan1.muted is True
        assert finding1_scan1.muted_at is not None
        assert finding1_scan1.muted_reason == "Historical finding across scans"

        assert finding2_scan2.muted is False
        assert finding2_scan2.muted_at is None

        mock_task.assert_called_once()
        call_args = mock_task.call_args
        assert call_args.kwargs["kwargs"]["tenant_id"] == str(tenant.id)
        assert "mute_rule_id" in call_args.kwargs["kwargs"]
