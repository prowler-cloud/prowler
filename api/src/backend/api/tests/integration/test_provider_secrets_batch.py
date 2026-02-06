import pytest
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from rest_framework import status

from api.models import Provider, ProviderSecret


@pytest.mark.django_db
class TestProviderSecretBatchCreate:
    """Tests for the batch provider secret creation endpoint."""

    content_type = "application/json"

    def test_batch_create_single_secret_success(
        self, authenticated_client, providers_fixture
    ):
        """Test creating a single provider secret via batch endpoint."""
        provider = providers_fixture[0]  # AWS provider

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "AWS Production Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == 1
        assert response_data["data"][0]["attributes"]["name"] == "AWS Production Secret"
        assert response_data["data"][0]["attributes"]["secret_type"] == "static"

    def test_batch_create_backwards_compatible_provider_singular(
        self, authenticated_client, providers_fixture
    ):
        """Test creating with backwards-compatible 'provider' (singular) format."""
        provider = providers_fixture[0]  # AWS provider

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "AWS Production Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "provider": {
                            "data": {"type": "providers", "id": str(provider.id)}
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == 1

    def test_batch_create_multiple_secrets_success(
        self, authenticated_client, tenants_fixture
    ):
        """Test creating multiple provider secrets in one batch."""
        tenant = tenants_fixture[0]

        # Create new providers without secrets for this test
        provider1 = Provider.objects.create(
            provider="aws",
            uid="111111111111",
            alias="aws_batch_1",
            tenant_id=tenant.id,
        )
        provider2 = Provider.objects.create(
            provider="gcp",
            uid="gcp-batch-project-1",
            alias="gcp_batch_1",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "AWS Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider1.id)}]
                        }
                    },
                },
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "GCP Secret",
                        "secret_type": "static",
                        "secret": {
                            "client_id": "123456789.apps.googleusercontent.com",
                            "client_secret": "GOCSPX-abcdefghijklmnop",
                            "refresh_token": "1//0abc-refresh-token-xyz",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider2.id)}]
                        }
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == 2

    def test_batch_create_one_secret_for_multiple_providers(
        self, authenticated_client, tenants_fixture
    ):
        """Test creating one secret definition that applies to multiple providers."""
        tenant = tenants_fixture[0]

        # Create multiple AWS providers
        provider1 = Provider.objects.create(
            provider="aws",
            uid="111111111111",
            alias="aws_multi_1",
            tenant_id=tenant.id,
        )
        provider2 = Provider.objects.create(
            provider="aws",
            uid="222222222222",
            alias="aws_multi_2",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Shared AWS Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [
                                {"type": "providers", "id": str(provider1.id)},
                                {"type": "providers", "id": str(provider2.id)},
                            ]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        # Should create 2 secrets (one per provider)
        assert len(response_data["data"]) == 2

    def test_batch_create_aws_role_secret(self, authenticated_client, tenants_fixture):
        """Test creating an AWS role assumption secret."""
        tenant = tenants_fixture[0]

        provider = Provider.objects.create(
            provider="aws",
            uid="222222222222",
            alias="aws_role_test",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "AWS Role Secret",
                        "secret_type": "role",
                        "secret": {
                            "role_arn": "arn:aws:iam::123456789012:role/ProwlerRole",
                            "external_id": "my-external-id-123",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == 1
        assert response_data["data"][0]["attributes"]["secret_type"] == "role"

    def test_batch_create_gcp_service_account_secret(
        self, authenticated_client, tenants_fixture
    ):
        """Test creating a GCP service account secret."""
        tenant = tenants_fixture[0]

        provider = Provider.objects.create(
            provider="gcp",
            uid="gcp-sa-test-project",
            alias="gcp_sa_test",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "GCP Service Account Secret",
                        "secret_type": "service_account",
                        "secret": {
                            "service_account_key": {
                                "type": "service_account",
                                "project_id": "my-project",
                                "private_key_id": "key123",
                                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
                                "client_email": "test@my-project.iam.gserviceaccount.com",
                                "client_id": "123456789",
                                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                                "token_uri": "https://oauth2.googleapis.com/token",
                            }
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == 1
        assert (
            response_data["data"][0]["attributes"]["secret_type"] == "service_account"
        )

    def test_batch_create_duplicate_provider_in_batch_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that duplicate providers in batch cause all-or-nothing failure."""
        tenant = tenants_fixture[0]
        initial_count = ProviderSecret.objects.count()

        provider = Provider.objects.create(
            provider="aws",
            uid="333333333333",
            alias="aws_dup_test",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "First Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                },
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Second Secret (duplicate provider)",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "TESTEXAMPLEKEY00002",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE2",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # All-or-nothing: should fail with 400
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Duplicate provider" in str(e.get("detail", "")) for e in errors)

        # Verify NO secrets were created
        assert ProviderSecret.objects.count() == initial_count

    def test_batch_create_provider_already_has_secret_skipped(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test that providers already having a secret are skipped and reported in meta."""
        # provider_secret_fixture creates secrets for all providers
        provider = providers_fixture[0]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Another Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # Should succeed with 201 but skip the provider
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        # No secrets created (all were skipped)
        assert len(response_data["data"]) == 0
        # Should have meta.skipped
        assert "meta" in response_data
        assert "skipped" in response_data["meta"]
        assert len(response_data["meta"]["skipped"]) == 1
        assert "already has a secret" in response_data["meta"]["skipped"][0]["reason"]

    def test_batch_create_mixed_skip_and_create(
        self,
        authenticated_client,
        tenants_fixture,
        providers_fixture,
        provider_secret_fixture,
    ):
        """Test batch with some providers skipped (already have secrets) and some created."""
        tenant = tenants_fixture[0]
        existing_provider = providers_fixture[0]  # Has secret from fixture

        # Create a new provider without a secret
        new_provider = Provider.objects.create(
            provider="aws",
            uid="999999999999",
            alias="aws_new_for_mixed",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Shared Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [
                                {
                                    "type": "providers",
                                    "id": str(existing_provider.id),
                                },  # Will be skipped
                                {
                                    "type": "providers",
                                    "id": str(new_provider.id),
                                },  # Will be created
                            ]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # One secret created for the new provider
        assert len(response_data["data"]) == 1

        # One skipped (existing provider already has secret)
        assert "meta" in response_data
        assert len(response_data["meta"]["skipped"]) == 1
        assert (
            str(existing_provider.id)
            == response_data["meta"]["skipped"][0]["provider_id"]
        )

    def test_batch_create_provider_not_found_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-existent providers cause all-or-nothing failure."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Secret for non-existent provider",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [
                                {
                                    "type": "providers",
                                    "id": "00000000-0000-0000-0000-000000000000",
                                }
                            ]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("not found" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_invalid_secret_type_for_provider_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that invalid secret_type for a provider causes all-or-nothing failure."""
        tenant = tenants_fixture[0]

        # GCP doesn't support role assumption
        provider = Provider.objects.create(
            provider="gcp",
            uid="gcp-invalid-type-test",
            alias="gcp_invalid_type",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Invalid Secret Type",
                        "secret_type": "role",
                        "secret": {
                            "role_arn": "arn:aws:iam::123456789012:role/ProwlerRole",
                            "external_id": "my-external-id",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("not supported" in str(e.get("detail", "")).lower() for e in errors)

    def test_batch_create_permission_denied(
        self, authenticated_client_no_permissions_rbac, tenants_fixture
    ):
        """Test that users without MANAGE_PROVIDERS permission cannot batch create."""
        tenant = tenants_fixture[0]

        provider = Provider.objects.create(
            provider="aws",
            uid="444444444444",
            alias="aws_perm_test",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client_no_permissions_rbac.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_batch_create_exceeds_limit_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests exceeding the limit are rejected."""
        limit = settings.API_BATCH_MAX_SIZE
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{i:012d}",
                alias=f"aws_limit_{i}",
                tenant_id=tenant.id,
            )
            for i in range(limit + 1)
        ]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": f"Secret {i}",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(providers[i].id)}]
                        }
                    },
                }
                for i in range(limit + 1)
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
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
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("At least one secret" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_invalid_data_format_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-array data is rejected."""
        payload = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "name": "Secret",
                    "secret_type": "static",
                    "secret": {
                        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    },
                },
            }
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Must be an array" in str(e.get("detail", "")) for e in errors)

    def test_batch_create_missing_providers_relationship_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that missing providers relationship is rejected."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Secret without provider",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {},
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any(
            "Providers relationship is required" in str(e.get("detail", ""))
            for e in errors
        )

    def test_batch_create_sets_correct_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch-created secrets have correct tenant assignment."""
        tenant = tenants_fixture[0]

        provider = Provider.objects.create(
            provider="aws",
            uid="666666666666",
            alias="aws_tenant_test",
            tenant_id=tenant.id,
        )

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Tenant Test Secret",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(provider.id)}]
                        }
                    },
                }
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )
        assert response.status_code == status.HTTP_201_CREATED
        secret_id = response.json()["data"][0]["id"]

        secret = ProviderSecret.objects.get(id=secret_id)
        assert secret.tenant_id == tenant.id

    def test_batch_create_multiple_errors_all_reported(
        self, authenticated_client, tenants_fixture
    ):
        """Test that all validation errors are reported (all-or-nothing)."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Secret 1",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [
                                {
                                    "type": "providers",
                                    "id": "00000000-0000-0000-0000-000000000001",
                                }
                            ]
                        }
                    },
                },
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Secret 2",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [
                                {
                                    "type": "providers",
                                    "id": "00000000-0000-0000-0000-000000000002",
                                }
                            ]
                        }
                    },
                },
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
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
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{700000000000 + i}",
                alias=f"aws_exact_limit_{i}",
                tenant_id=tenant.id,
            )
            for i in range(limit)
        ]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": f"Secret {i}",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(providers[i].id)}]
                        }
                    },
                }
                for i in range(limit)
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert len(response_data["data"]) == limit

    @override_settings(API_BATCH_MAX_SIZE=5)
    def test_batch_create_respects_custom_limit_setting(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch endpoint respects custom API_BATCH_MAX_SIZE setting."""
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{900000000000 + i}",
                alias=f"aws_custom_limit_{i}",
                tenant_id=tenant.id,
            )
            for i in range(6)
        ]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": f"Secret {i}",
                        "secret_type": "static",
                        "secret": {
                            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                        },
                    },
                    "relationships": {
                        "providers": {
                            "data": [{"type": "providers", "id": str(providers[i].id)}]
                        }
                    },
                }
                for i in range(6)
            ]
        }

        response = authenticated_client.post(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Maximum 5" in str(e.get("detail", "")) for e in errors)


@pytest.mark.django_db
class TestProviderSecretBatchUpdate:
    """Tests for the batch provider secret update endpoint."""

    content_type = "application/json"

    def test_batch_update_single_secret_success(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test updating a single provider secret via batch endpoint."""
        secret = provider_secret_fixture[0]
        new_name = "Updated AWS Secret Name"

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "name": new_name,
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 1
        assert data[0]["attributes"]["name"] == new_name

        secret.refresh_from_db()
        assert secret.name == new_name

    def test_batch_update_multiple_secrets_success(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test updating multiple provider secrets in one batch."""
        secret1 = provider_secret_fixture[0]
        secret2 = provider_secret_fixture[1]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret1.id),
                    "attributes": {
                        "name": "Updated Secret 1",
                    },
                },
                {
                    "type": "provider-secrets",
                    "id": str(secret2.id),
                    "attributes": {
                        "name": "Updated Secret 2",
                    },
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == 2

        secret1.refresh_from_db()
        secret2.refresh_from_db()
        assert secret1.name == "Updated Secret 1"
        assert secret2.name == "Updated Secret 2"

    def test_batch_update_secret_credentials(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test updating secret credentials via batch endpoint."""
        secret = provider_secret_fixture[0]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "secret": {
                            "aws_access_key_id": "NEWAKIAIOSFODNN7EXAMPLE",
                            "aws_secret_access_key": "NEWwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        },
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK

    def test_batch_update_secret_not_found_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-existent secrets cause all-or-nothing failure."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": "00000000-0000-0000-0000-000000000000",
                    "attributes": {
                        "name": "Updated Name",
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("not found" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_duplicate_id_in_batch_error(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test that duplicate IDs cause all-or-nothing failure."""
        secret = provider_secret_fixture[0]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "name": "First Update",
                    },
                },
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "name": "Second Update (duplicate)",
                    },
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        # All-or-nothing: should fail with 400
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Duplicate secret ID" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_missing_id_error(self, authenticated_client, tenants_fixture):
        """Test that missing ID is rejected."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "attributes": {
                        "name": "Updated Name",
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("required" in str(e.get("detail", "")).lower() for e in errors)

    def test_batch_update_permission_denied(
        self,
        authenticated_client_no_permissions_rbac,
        providers_fixture,
        provider_secret_fixture,
    ):
        """Test that users without MANAGE_PROVIDERS permission cannot batch update."""
        secret = provider_secret_fixture[0]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "name": "Updated Name",
                    },
                }
            ]
        }

        response = authenticated_client_no_permissions_rbac.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_batch_update_exceeds_limit_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that batch requests exceeding the limit are rejected."""
        limit = settings.API_BATCH_MAX_SIZE
        tenant = tenants_fixture[0]

        providers = [
            Provider.objects.create(
                provider="aws",
                uid=f"{i:012d}",
                alias=f"aws_update_limit_{i}",
                tenant_id=tenant.id,
            )
            for i in range(limit + 1)
        ]

        secrets = [
            ProviderSecret.objects.create(
                provider=providers[i],
                tenant_id=tenant.id,
                name=f"Secret {i}",
                secret_type="static",
                secret={
                    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                },
            )
            for i in range(limit + 1)
        ]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secrets[i].id),
                    "attributes": {
                        "name": f"Updated Secret {i}",
                    },
                }
                for i in range(limit + 1)
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
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
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("At least one secret" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_invalid_data_format_error(
        self, authenticated_client, tenants_fixture
    ):
        """Test that non-array data is rejected."""
        payload = {
            "data": {
                "type": "provider-secrets",
                "id": "00000000-0000-0000-0000-000000000000",
                "attributes": {
                    "name": "Updated Name",
                },
            }
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
        assert any("Must be an array" in str(e.get("detail", "")) for e in errors)

    def test_batch_update_preserves_other_fields(
        self, authenticated_client, providers_fixture, provider_secret_fixture
    ):
        """Test that updating one field doesn't affect other fields."""
        secret = provider_secret_fixture[0]
        original_secret_type = secret.secret_type

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secret.id),
                    "attributes": {
                        "name": "Only Name Updated",
                    },
                }
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK

        secret.refresh_from_db()
        assert secret.name == "Only Name Updated"
        assert secret.secret_type == original_secret_type

    def test_batch_update_multiple_errors_all_reported(
        self, authenticated_client, tenants_fixture
    ):
        """Test that all validation errors are reported (all-or-nothing)."""
        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": "00000000-0000-0000-0000-000000000001",
                    "attributes": {
                        "name": "Secret 1",
                    },
                },
                {
                    "type": "provider-secrets",
                    "id": "00000000-0000-0000-0000-000000000002",
                    "attributes": {
                        "name": "Secret 2",
                    },
                },
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        errors = response.json()["errors"]
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
                uid=f"{400000000000 + i}",
                alias=f"aws_update_exact_{i}",
                tenant_id=tenant.id,
            )
            for i in range(limit)
        ]

        secrets = [
            ProviderSecret.objects.create(
                provider=providers[i],
                tenant_id=tenant.id,
                name=f"Secret {i}",
                secret_type="static",
                secret={
                    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                },
            )
            for i in range(limit)
        ]

        payload = {
            "data": [
                {
                    "type": "provider-secrets",
                    "id": str(secrets[i].id),
                    "attributes": {
                        "name": f"Updated Secret {i}",
                    },
                }
                for i in range(limit)
            ]
        }

        response = authenticated_client.patch(
            reverse("providersecret-batch"),
            data=payload,
            content_type=self.content_type,
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()["data"]
        assert len(data) == limit
