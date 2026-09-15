import json

import pytest
from api.models import TenantOnboardingProfile
from conftest import API_JSON_CONTENT_TYPE
from django.urls import reverse
from rest_framework import status

ANSWERS = {
    "declared_cloud_accounts": "11-50",
    "declared_team_size": "2-5",
    "declared_role": "security",
}


def _submit(client, attributes):
    payload = {"data": {"type": "onboarding-profiles", "attributes": attributes}}
    return client.post(
        reverse("onboarding-profile-list"),
        data=json.dumps(payload),
        content_type=API_JSON_CONTENT_TYPE,
    )


def _error_pointers(response):
    return [error["source"]["pointer"] for error in response.json()["errors"]]


@pytest.mark.django_db
class TestTenantOnboardingProfileViewSet:
    def test_declares_the_profile_once(
        self, authenticated_client, tenants_fixture, create_test_user
    ):
        response = _submit(authenticated_client, ANSWERS)

        assert response.status_code == status.HTTP_201_CREATED
        attributes = response.json()["data"]["attributes"]
        assert attributes["declared_cloud_accounts"] == "11-50"
        assert attributes["declared_team_size"] == "2-5"
        assert attributes["declared_role"] == "security"
        assert attributes["skipped"] is False
        profile = TenantOnboardingProfile.objects.get(tenant_id=tenants_fixture[0].id)
        assert profile.submitted_by_id == create_test_user.id

    def test_records_a_skip_as_a_fact(self, authenticated_client, tenants_fixture):
        response = _submit(authenticated_client, {"skipped": True})

        assert response.status_code == status.HTTP_201_CREATED
        attributes = response.json()["data"]["attributes"]
        assert attributes["skipped"] is True
        assert attributes["declared_role"] is None
        assert TenantOnboardingProfile.objects.filter(
            tenant_id=tenants_fixture[0].id, skipped=True
        ).exists()

    def test_second_submission_keeps_the_first_answer(self, authenticated_client):
        first = _submit(authenticated_client, ANSWERS)
        second = _submit(
            authenticated_client, {**ANSWERS, "declared_role": "management"}
        )

        assert first.status_code == status.HTTP_201_CREATED
        assert second.status_code == status.HTTP_200_OK
        assert second.json()["data"]["id"] == first.json()["data"]["id"]
        assert second.json()["data"]["attributes"]["declared_role"] == "security"
        assert TenantOnboardingProfile.objects.count() == 1

    def test_a_skip_cannot_replace_an_answer(self, authenticated_client):
        _submit(authenticated_client, ANSWERS)

        response = _submit(authenticated_client, {"skipped": True})

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["skipped"] is False

    @pytest.mark.parametrize(
        "attributes, pointer",
        [
            (
                {"declared_cloud_accounts": "1", "declared_team_size": "1"},
                "/data/attributes/declared_role",
            ),
            ({}, "/data/attributes/declared_cloud_accounts"),
            (
                {"skipped": True, "declared_role": "developer"},
                "/data/attributes/declared_role",
            ),
            (
                {**ANSWERS, "declared_cloud_accounts": "1000"},
                "/data/attributes/declared_cloud_accounts",
            ),
            (
                {**ANSWERS, "declared_role": "ceo"},
                "/data/attributes/declared_role",
            ),
            ({**ANSWERS, "company": "Acme"}, "/data"),
        ],
    )
    def test_rejects_incomplete_or_unknown_answers(
        self, authenticated_client, attributes, pointer
    ):
        response = _submit(authenticated_client, attributes)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert pointer in _error_pointers(response)
        assert not TenantOnboardingProfile.objects.exists()

    def test_lists_only_the_tenant_profile(
        self,
        authenticated_client,
        authenticated_client_for_tenant_factory,
        create_test_user,
        tenants_fixture,
    ):
        other_client = authenticated_client_for_tenant_factory(
            create_test_user, tenants_fixture[1]
        )
        _submit(authenticated_client, ANSWERS)
        _submit(other_client, {"skipped": True})

        own = authenticated_client.get(reverse("onboarding-profile-list"))
        other = other_client.get(reverse("onboarding-profile-list"))

        assert own.status_code == status.HTTP_200_OK
        assert [entry["attributes"]["skipped"] for entry in own.json()["data"]] == [
            False
        ]
        assert [entry["attributes"]["skipped"] for entry in other.json()["data"]] == [
            True
        ]

    def test_empty_list_before_the_step_runs(self, authenticated_client):
        response = authenticated_client.get(reverse("onboarding-profile-list"))

        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"] == []

    def test_members_without_permissions_can_answer(
        self, authenticated_client_no_permissions_rbac
    ):
        response = _submit(authenticated_client_no_permissions_rbac, ANSWERS)

        assert response.status_code == status.HTTP_201_CREATED
