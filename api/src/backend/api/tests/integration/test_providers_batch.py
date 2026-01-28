import uuid

import pytest
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from api.models import Provider


@pytest.mark.django_db
class TestProviderBatchCreate:
    """Tests for the batch provider creation endpoint."""

    content_type = "application/json"

    def test_batch_create_single_provider_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test creating a single provider via batch endpoint."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "111111111111",
                        "alias": "Test AWS Account",
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["provider"] == "aws"
        assert data[0]["attributes"]["uid"] == "111111111111"
        assert data[0]["attributes"]["alias"] == "Test AWS Account"

    def test_batch_create_multiple_providers_mixed_types(
        self, authenticated_client, tenants_fixture
    ):
        """Test creating multiple providers of different types in one batch."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "222222222222",
                        "alias": "AWS Account 1",
                    },
                },
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "azure",
                        "uid": "a1b2c3d4-e5f6-4890-abcd-ef1234567890",
                        "alias": "Azure Subscription",
                    },
                },
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "gcp",
                        "uid": "my-gcp-project-id",
                        "alias": "GCP Project",
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()["data"]
        assert len(data) == 3

        providers_by_type = {p["attributes"]["provider"]: p for p in data}
        assert "aws" in providers_by_type
        assert "azure" in providers_by_type
        assert "gcp" in providers_by_type

    def test_batch_create_duplicate_uid_in_batch_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that duplicate UIDs within same batch fails entire batch (all-or-nothing)."""
        initial_count = Provider.objects.count()

        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "444444444444",
                        "alias": "AWS Account 1",
                    },
                },
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "444444444444",
                        "alias": "AWS Account 2 (duplicate)",
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # All-or-nothing: entire batch fails
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]

        # Should have duplicate error
        assert any("Duplicate UID" in str(e.get("detail", "")) for e in errors)

        # Verify no providers were created
        assert Provider.objects.count() == initial_count

    def test_batch_create_existing_uid_error(
        self, authenticated_client, providers_fixture
    ):
        """Test that UIDs already existing in tenant are rejected."""
        existing_provider = providers_fixture[0]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": existing_provider.provider,
                        "uid": existing_provider.uid,
                        "alias": "Duplicate of existing",
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("already exists" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_invalid_uid_format_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that invalid UID formats are rejected with proper error messages."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "invalid-aws-uid",
                        "alias": "Invalid AWS",
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("/data/0/attributes" in str(e.get("source", {})) for e in errors)

    def test_batch_create_permission_denied(
        self, authenticated_client_no_permissions_rbac, tenants_fixture
    ):
        """Test that users without MANAGE_PROVIDERS permission cannot batch create."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "555555555555",
                        "alias": "Test",
                    },
                }
            ]
        }

        response = authenticated_client_no_permissions_rbac.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_batch_create_exceeds_limit_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests exceeding the limit are rejected."""
        limit = settings.API_BATCH_MAX_SIZE
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": f"{i:012d}",
                        "alias": f"Provider {i}",
                    },
                }
                for i in range(limit + 1)
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any(f"Maximum {limit}" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_empty_array_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that empty batch requests are rejected."""
        payload = {"data": []}

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("At least one provider" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_invalid_data_format_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-array data is rejected."""
        payload = {
            "data": {
                "type": "providers",
                "attributes": {
                    "provider": "aws",
                    "uid": "666666666666",
                },
            }
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Must be an array" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_sets_correct_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch-created providers have correct tenant assignment."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "777777777777",
                        "alias": "Tenant 1 Provider",
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )
        assert response.status_code == status.HTTP_201_CREATED
        provider_id = response.json()["data"][0]["id"]

        provider = Provider.objects.get(id=provider_id)
        assert provider.tenant_id == tenants_fixture[0].id

    def test_batch_create_mixed_valid_invalid_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that mixed valid/invalid items fails entire batch (all-or-nothing)."""
        initial_count = Provider.objects.count()

        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "888888888888",
                        "alias": "Valid AWS",
                    },
                },
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "invalid-uid",
                        "alias": "Invalid AWS",
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # All-or-nothing: entire batch fails
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]

        # Should have error for invalid item
        assert len(errors) >= 1
        assert any(
            "/data/1" in str(e.get("source", {}).get("pointer", "")) for e in errors
        )

        # No providers should have been created
        assert Provider.objects.count() == initial_count

    def test_batch_create_multiple_errors_reported(
        self, authenticated_client, tenants_fixture
    ):
        """Test that all validation errors are reported, not just the first one."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "invalid1",
                        "alias": "Invalid 1",
                    },
                },
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "azure",
                        "uid": "not-a-uuid",
                        "alias": "Invalid 2",
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        # Should have errors for both items
        error_pointers = [e.get("source", {}).get("pointer", "") for e in errors]
        assert any("/data/0" in p for p in error_pointers)
        assert any("/data/1" in p for p in error_pointers)

    def test_batch_create_at_exact_limit_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests at exactly the limit are accepted."""
        limit = settings.API_BATCH_MAX_SIZE
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": f"{i:012d}",
                        "alias": f"Provider {i}",
                    },
                }
                for i in range(limit)
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()["data"]
        assert len(data) == limit

    @override_settings(API_BATCH_MAX_SIZE=5)
    def test_batch_create_respects_custom_limit_setting(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch endpoint respects custom API_BATCH_MAX_SIZE setting."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": f"{900000000000 + i}",
                        "alias": f"Provider {i}",
                    },
                }
                for i in range(6)
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Maximum 5" in str(e.get("detail", "")) for e in errors)

    @override_settings(API_BATCH_MAX_SIZE=3)
    def test_batch_create_at_custom_limit_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests at exactly the custom limit are accepted."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": f"{800000000000 + i}",
                        "alias": f"Provider {i}",
                    },
                }
                for i in range(3)
            ]
        }

        response = authenticated_client.post(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()["data"]
        assert len(data) == 3


@pytest.mark.django_db
class TestProviderBatchUpdate:
    """Tests for the batch provider update endpoint."""

    content_type = "application/json"

    def test_batch_update_single_provider_success(
        self, authenticated_client, providers_fixture
    ):
        """Test updating a single provider via batch endpoint."""
        provider = providers_fixture[0]
        new_alias = "Updated AWS Account"

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {
                        "alias": new_alias,
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["alias"] == new_alias

        # Verify in database
        provider.refresh_from_db()
        assert provider.alias == new_alias

    def test_batch_update_multiple_providers_success(
        self, authenticated_client, providers_fixture
    ):
        """Test updating multiple providers in one batch."""
        provider1 = providers_fixture[0]
        provider2 = providers_fixture[1]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider1.id),
                    "attributes": {"alias": "Updated Provider 1"},
                },
                {
                    "type": "providers",
                    "id": str(provider2.id),
                    "attributes": {"alias": "Updated Provider 2"},
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2

        # Verify in database
        provider1.refresh_from_db()
        provider2.refresh_from_db()
        assert provider1.alias == "Updated Provider 1"
        assert provider2.alias == "Updated Provider 2"

    def test_batch_update_provider_not_found_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-existent providers are rejected."""
        fake_id = str(uuid.uuid4())

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": fake_id,
                    "attributes": {"alias": "New Alias"},
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("not found" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_duplicate_id_in_batch_error(
        self, authenticated_client, providers_fixture
    ):
        """Test that duplicate IDs within same batch fails entire batch (all-or-nothing)."""
        provider = providers_fixture[0]
        original_alias = provider.alias

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {"alias": "First Update"},
                },
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {"alias": "Second Update (duplicate)"},
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # All-or-nothing: entire batch fails
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]

        # Should have duplicate error
        assert any("Duplicate provider ID" in str(e.get("detail", "")) for e in errors)

        # Verify provider was not updated
        provider.refresh_from_db()
        assert provider.alias == original_alias

    def test_batch_update_permission_denied(
        self, authenticated_client_no_permissions_rbac, providers_fixture
    ):
        """Test that users without MANAGE_PROVIDERS permission cannot batch update."""
        provider = providers_fixture[0]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {"alias": "New Alias"},
                }
            ]
        }

        response = authenticated_client_no_permissions_rbac.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_batch_update_exceeds_limit_error(
        self, authenticated_client, providers_fixture
    ):
        """Test that batch requests exceeding the limit are rejected."""
        limit = settings.API_BATCH_MAX_SIZE
        provider = providers_fixture[0]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {"alias": f"Provider {i}"},
                }
                for i in range(limit + 1)
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any(f"Maximum {limit}" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_empty_array_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that empty batch requests are rejected."""
        payload = {"data": []}

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("At least one provider" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_invalid_data_format_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-array data is rejected."""
        payload = {
            "data": {
                "type": "providers",
                "id": str(uuid.uuid4()),
                "attributes": {"alias": "Test"},
            }
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Must be an array" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_missing_id_error(self, authenticated_client, tenants_fixture):
        """Test that missing ID is rejected."""
        payload = {
            "data": [
                {
                    "type": "providers",
                    "attributes": {"alias": "New Alias"},
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("required" in str(e.get("detail", "")).lower() for e in errors)

    def test_batch_update_preserves_other_fields(
        self, authenticated_client, providers_fixture
    ):
        """Test that updating alias doesn't change other fields."""
        provider = providers_fixture[0]
        original_uid = provider.uid
        original_provider_type = provider.provider

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(provider.id),
                    "attributes": {"alias": "Updated Alias Only"},
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK

        provider.refresh_from_db()
        assert provider.alias == "Updated Alias Only"
        assert provider.uid == original_uid
        assert provider.provider == original_provider_type

    def test_batch_update_multiple_errors_reported(
        self, authenticated_client, tenants_fixture
    ):
        """Test that all validation errors are reported, not just the first one."""
        fake_id1 = str(uuid.uuid4())
        fake_id2 = str(uuid.uuid4())

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": fake_id1,
                    "attributes": {"alias": "Provider 1"},
                },
                {
                    "type": "providers",
                    "id": fake_id2,
                    "attributes": {"alias": "Provider 2"},
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        # Should have errors for both items
        error_pointers = [e.get("source", {}).get("pointer", "") for e in errors]
        assert any("/data/0" in p for p in error_pointers)
        assert any("/data/1" in p for p in error_pointers)

    def test_batch_update_at_exact_limit_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests at exactly the limit are accepted."""
        limit = settings.API_BATCH_MAX_SIZE
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{700000000000 + i}",
                alias=f"Provider {i}",
                tenant_id=tenant.id,
            )
            for i in range(limit)
        ]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(providers[i].id),
                    "attributes": {"alias": f"Updated Provider {i}"},
                }
                for i in range(limit)
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == limit

    @override_settings(API_BATCH_MAX_SIZE=5)
    def test_batch_update_respects_custom_limit_setting(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch update endpoint respects custom API_BATCH_MAX_SIZE setting."""
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{600000000000 + i}",
                alias=f"Provider {i}",
                tenant_id=tenant.id,
            )
            for i in range(6)
        ]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(providers[i].id),
                    "attributes": {"alias": f"Updated Provider {i}"},
                }
                for i in range(6)
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Maximum 5" in str(e.get("detail", "")) for e in errors)

    @override_settings(API_BATCH_MAX_SIZE=3)
    def test_batch_update_at_custom_limit_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests at exactly the custom limit are accepted."""
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{500000000000 + i}",
                alias=f"Provider {i}",
                tenant_id=tenant.id,
            )
            for i in range(3)
        ]

        payload = {
            "data": [
                {
                    "type": "providers",
                    "id": str(providers[i].id),
                    "attributes": {"alias": f"Updated Provider {i}"},
                }
                for i in range(3)
            ]
        }

        response = authenticated_client.patch(
            reverse("provider-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 3
