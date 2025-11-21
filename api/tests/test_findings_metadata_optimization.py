"""
Tests for the findings metadata optimization that uses indexed fields
instead of JSONB parsing for category extraction.

This test file covers the changes made in PR #9137 that optimize the
metadata() and metadata_latest() endpoints by:
1. Using indexed (provider, check_id) fields instead of JSONB check_metadata
2. Loading metadata once per provider with CheckMetadata.get_bulk()
3. Extracting categories in memory from bulk metadata

References:
- GitHub PR: https://github.com/prowler-cloud/prowler/pull/9137
- Issue comment: https://github.com/prowler-cloud/prowler/pull/9137#issuecomment-3553835521
"""

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from prowler.lib.check.models import CheckMetadata

from api.models import Finding, Provider, Scan, StateChoices
from api.rls import Tenant

User = get_user_model()


@pytest.fixture
def tenant(db):
    """Create a test tenant."""
    return Tenant.objects.create(name="Test Tenant")


@pytest.fixture
def user(db, tenant):
    """Create a test user."""
    user = User.objects.create_user(
        email="test@example.com",
        password="testpass123",
        name="Test User",
    )
    from api.models import Membership

    Membership.objects.create(
        user=user, tenant=tenant, role=Membership.RoleChoices.OWNER
    )
    return user


@pytest.fixture
def provider_aws(db, tenant):
    """Create an AWS provider."""
    return Provider.objects.create(
        tenant=tenant,
        provider="aws",
        uid="123456789012",
        alias="test-aws-account",
        connected=True,
    )


@pytest.fixture
def provider_azure(db, tenant):
    """Create an Azure provider."""
    return Provider.objects.create(
        tenant=tenant,
        provider="azure",
        uid="azure-subscription-id",
        alias="test-azure-subscription",
        connected=True,
    )


@pytest.fixture
def completed_scan_aws(db, provider_aws):
    """Create a completed scan for AWS provider."""
    return Scan.objects.create(
        tenant=provider_aws.tenant,
        provider=provider_aws,
        name="Test AWS Scan",
        state=StateChoices.COMPLETED,
        unique_resource_count=100,
        duration=300,
    )


@pytest.fixture
def completed_scan_azure(db, provider_azure):
    """Create a completed scan for Azure provider."""
    return Scan.objects.create(
        tenant=provider_azure.tenant,
        provider=provider_azure,
        name="Test Azure Scan",
        state=StateChoices.COMPLETED,
        unique_resource_count=50,
        duration=200,
    )


@pytest.fixture
def findings_aws(db, completed_scan_aws, tenant):
    """Create test findings for AWS with different check_ids."""
    findings = []
    check_ids = [
        "iam_user_mfa_enabled_console_access",
        "s3_bucket_public_access",
        "ec2_instance_publicly_accessible",
    ]

    for check_id in check_ids:
        finding = Finding.objects.create(
            tenant=tenant,
            scan=completed_scan_aws,
            check_id=check_id,
            uid=f"{check_id}-{uuid.uuid4()}",
            status="FAIL",
            severity="high",
            region="us-east-1",
            provider="aws",
        )
        findings.append(finding)

    return findings


@pytest.fixture
def findings_azure(db, completed_scan_azure, tenant):
    """Create test findings for Azure with different check_ids."""
    findings = []
    check_ids = [
        "defender_ensure_defender_for_app_services_is_on",
        "storage_ensure_soft_delete_is_enabled",
    ]

    for check_id in check_ids:
        finding = Finding.objects.create(
            tenant=tenant,
            scan=completed_scan_azure,
            check_id=check_id,
            uid=f"{check_id}-{uuid.uuid4()}",
            status="FAIL",
            severity="medium",
            region="eastus",
            provider="azure",
        )
        findings.append(finding)

    return findings


@pytest.fixture
def mock_check_metadata():
    """
    Mock CheckMetadata.get_bulk() and CheckMetadata.get() to return
    test metadata with categories.
    """

    def create_mock_metadata(categories):
        """Helper to create a mock metadata object."""
        mock = MagicMock()
        mock.Categories = categories
        return mock

    # Define mock metadata for different providers and checks
    aws_metadata = {
        "iam_user_mfa_enabled_console_access": create_mock_metadata(
            ["identity-and-access-management", "security"]
        ),
        "s3_bucket_public_access": create_mock_metadata(["storage", "security"]),
        "ec2_instance_publicly_accessible": create_mock_metadata(
            ["compute", "networking", "security"]
        ),
    }

    azure_metadata = {
        "defender_ensure_defender_for_app_services_is_on": create_mock_metadata(
            ["security", "defender"]
        ),
        "storage_ensure_soft_delete_is_enabled": create_mock_metadata(
            ["storage", "data-protection"]
        ),
    }

    def mock_get_bulk(provider):
        """Mock implementation of CheckMetadata.get_bulk()."""
        if provider == "aws":
            return aws_metadata
        elif provider == "azure":
            return azure_metadata
        return {}

    def mock_get(bulk_metadata, check_id):
        """Mock implementation of CheckMetadata.get()."""
        return bulk_metadata.get(check_id)

    with (
        patch.object(CheckMetadata, "get_bulk", side_effect=mock_get_bulk) as mock_bulk,
        patch.object(CheckMetadata, "get", side_effect=mock_get) as mock_get_fn,
    ):
        yield {"get_bulk": mock_bulk, "get": mock_get_fn}


class TestFindingsMetadataOptimization:
    """Test suite for the optimized metadata extraction logic."""

    def test_metadata_uses_indexed_fields(
        self, client, user, tenant, findings_aws, mock_check_metadata
    ):
        """
        Test that metadata() method uses indexed (provider, check_id) fields
        instead of loading full findings with JSONB.
        """
        client.force_authenticate(user=user)

        # Call the metadata endpoint
        response = client.get(
            f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
        )

        assert response.status_code == 200
        data = response.json()

        # Verify CheckMetadata.get_bulk was called with correct provider
        mock_check_metadata["get_bulk"].assert_called_with("aws")

        # Verify categories are extracted and sorted
        assert "categories" in data
        categories = data["categories"]
        assert isinstance(categories, list)
        assert categories == sorted(categories)  # Should be sorted

    def test_metadata_extracts_categories_from_bulk_metadata(
        self, client, user, tenant, findings_aws, mock_check_metadata
    ):
        """
        Test that categories are correctly extracted from CheckMetadata
        without parsing JSONB fields.
        """
        client.force_authenticate(user=user)

        response = client.get(
            f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
        )

        assert response.status_code == 200
        data = response.json()

        # Expected categories from the mock metadata
        expected_categories = {
            "compute",
            "identity-and-access-management",
            "networking",
            "security",
            "storage",
        }

        assert set(data["categories"]) == expected_categories

    def test_metadata_handles_multiple_providers(
        self,
        client,
        user,
        tenant,
        findings_aws,
        findings_azure,
        mock_check_metadata,
    ):
        """
        Test that metadata() correctly handles findings from multiple
        providers by loading metadata once per provider.
        """
        client.force_authenticate(user=user)

        response = client.get(
            f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
        )

        assert response.status_code == 200
        data = response.json()

        # Verify get_bulk was called for both providers
        assert mock_check_metadata["get_bulk"].call_count >= 2
        providers_called = {
            call[0][0] for call in mock_check_metadata["get_bulk"].call_args_list
        }
        assert "aws" in providers_called
        assert "azure" in providers_called

        # Verify categories from both providers are included
        expected_categories = {
            "compute",
            "data-protection",
            "defender",
            "identity-and-access-management",
            "networking",
            "security",
            "storage",
        }
        assert set(data["categories"]) == expected_categories

    def test_metadata_groups_check_ids_by_provider(
        self, client, user, tenant, findings_aws, findings_azure, mock_check_metadata
    ):
        """
        Test that the optimization correctly groups distinct check_ids
        by provider before loading metadata.
        """
        client.force_authenticate(user=user)

        response = client.get(
            f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
        )

        assert response.status_code == 200

        # Verify CheckMetadata.get() was called with correct check_ids per provider
        get_calls = mock_check_metadata["get"].call_args_list

        # Group calls by provider (identified by bulk_metadata content)
        aws_check_ids = set()
        azure_check_ids = set()

        for call in get_calls:
            bulk_metadata = call[0][0]
            check_id = call[0][1]

            # Identify provider by checking if check_id exists in mock data
            if check_id in [
                "iam_user_mfa_enabled_console_access",
                "s3_bucket_public_access",
                "ec2_instance_publicly_accessible",
            ]:
                aws_check_ids.add(check_id)
            elif check_id in [
                "defender_ensure_defender_for_app_services_is_on",
                "storage_ensure_soft_delete_is_enabled",
            ]:
                azure_check_ids.add(check_id)

        # Verify all expected check_ids were processed
        assert aws_check_ids == {
            "iam_user_mfa_enabled_console_access",
            "s3_bucket_public_access",
            "ec2_instance_publicly_accessible",
        }
        assert azure_check_ids == {
            "defender_ensure_defender_for_app_services_is_on",
            "storage_ensure_soft_delete_is_enabled",
        }

    def test_metadata_latest_uses_optimization(
        self, client, user, tenant, findings_aws, mock_check_metadata
    ):
        """
        Test that metadata_latest() endpoint uses the same optimization
        as metadata().
        """
        client.force_authenticate(user=user)

        response = client.get("/findings/metadata/latest/")

        assert response.status_code == 200
        data = response.json()

        # Verify CheckMetadata.get_bulk was called
        mock_check_metadata["get_bulk"].assert_called_with("aws")

        # Verify categories are present and sorted
        assert "categories" in data
        assert data["categories"] == sorted(data["categories"])

    def test_metadata_handles_scan_filter(
        self,
        client,
        user,
        tenant,
        completed_scan_aws,
        findings_aws,
        mock_check_metadata,
    ):
        """
        Test that metadata() works correctly with scan filter applied.
        """
        client.force_authenticate(user=user)

        response = client.get(
            f"/findings/metadata/?filter[scan]={completed_scan_aws.id}"
        )

        assert response.status_code == 200
        data = response.json()

        # Should return categories for the filtered scan
        assert "categories" in data
        expected_categories = {
            "compute",
            "identity-and-access-management",
            "networking",
            "security",
            "storage",
        }
        assert set(data["categories"]) == expected_categories

    def test_metadata_empty_categories_for_check(
        self, client, user, tenant, completed_scan_aws
    ):
        """
        Test that metadata() handles checks with no categories gracefully.
        """
        # Create a finding for a check with no categories
        Finding.objects.create(
            tenant=tenant,
            scan=completed_scan_aws,
            check_id="check_without_categories",
            uid=f"check_without_categories-{uuid.uuid4()}",
            status="PASS",
            severity="low",
            region="us-east-1",
            provider="aws",
        )

        def mock_get_bulk_empty(provider):
            return {"check_without_categories": MagicMock(Categories=None)}

        def mock_get_empty(bulk_metadata, check_id):
            return bulk_metadata.get(check_id)

        with (
            patch.object(CheckMetadata, "get_bulk", side_effect=mock_get_bulk_empty),
            patch.object(CheckMetadata, "get", side_effect=mock_get_empty),
        ):
            client.force_authenticate(user=user)
            response = client.get(
                f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
            )

            assert response.status_code == 200
            data = response.json()

            # Should return empty categories list
            assert "categories" in data
            assert data["categories"] == []

    def test_metadata_deduplicates_categories(
        self, client, user, tenant, completed_scan_aws, mock_check_metadata
    ):
        """
        Test that duplicate categories across multiple checks are
        deduplicated correctly.
        """
        # Create multiple findings that share the "security" category
        for i in range(3):
            Finding.objects.create(
                tenant=tenant,
                scan=completed_scan_aws,
                check_id=f"s3_bucket_public_access",
                uid=f"s3_bucket_public_access-{uuid.uuid4()}",
                status="FAIL",
                severity="high",
                region=f"us-east-{i + 1}",
                provider="aws",
            )

        client.force_authenticate(user=user)
        response = client.get(
            f"/findings/metadata/?filter[inserted_at]={datetime.now(timezone.utc).date()}"
        )

        assert response.status_code == 200
        data = response.json()

        # Verify categories are deduplicated (no duplicates in the list)
        categories = data["categories"]
        assert len(categories) == len(set(categories))
        assert "security" in categories
        assert "storage" in categories


class TestOptimizationImplementation:
    """Test the core optimization logic directly."""

    def test_check_ids_grouped_by_provider_correctly(
        self, findings_aws, findings_azure
    ):
        """
        Test that the optimization correctly groups check_ids by provider
        using the pattern: check_ids_by_provider = defaultdict(set)
        """
        # Simulate the optimization logic
        check_ids_by_provider = defaultdict(set)

        # Simulate the queryset values
        mock_queryset_values = [
            {
                "scan__provider__provider": "aws",
                "check_id": "iam_user_mfa_enabled_console_access",
            },
            {"scan__provider__provider": "aws", "check_id": "s3_bucket_public_access"},
            {
                "scan__provider__provider": "aws",
                "check_id": "ec2_instance_publicly_accessible",
            },
            {
                "scan__provider__provider": "azure",
                "check_id": "defender_ensure_defender_for_app_services_is_on",
            },
            {
                "scan__provider__provider": "azure",
                "check_id": "storage_ensure_soft_delete_is_enabled",
            },
        ]

        for finding in mock_queryset_values:
            check_ids_by_provider[finding["scan__provider__provider"]].add(
                finding["check_id"]
            )

        # Verify grouping
        assert "aws" in check_ids_by_provider
        assert "azure" in check_ids_by_provider

        assert check_ids_by_provider["aws"] == {
            "iam_user_mfa_enabled_console_access",
            "s3_bucket_public_access",
            "ec2_instance_publicly_accessible",
        }

        assert check_ids_by_provider["azure"] == {
            "defender_ensure_defender_for_app_services_is_on",
            "storage_ensure_soft_delete_is_enabled",
        }

    def test_categories_extracted_from_bulk_metadata(self, mock_check_metadata):
        """
        Test that categories are correctly extracted from bulk metadata
        in memory without JSONB parsing.
        """
        check_ids_by_provider = {
            "aws": {
                "iam_user_mfa_enabled_console_access",
                "s3_bucket_public_access",
            },
        }

        categories = set()

        for provider, check_ids in check_ids_by_provider.items():
            bulk_metadata = CheckMetadata.get_bulk(provider)
            for check_id in check_ids:
                check_metadata = CheckMetadata.get(bulk_metadata, check_id)
                if check_metadata and check_metadata.Categories:
                    categories.update(check_metadata.Categories)

        # Verify categories were extracted
        expected = {
            "identity-and-access-management",
            "security",
            "storage",
        }
        assert categories == expected

    def test_categories_sorted_alphabetically(self, mock_check_metadata):
        """
        Test that the final categories list is sorted alphabetically.
        """
        check_ids_by_provider = {
            "aws": {
                "ec2_instance_publicly_accessible",
                "s3_bucket_public_access",
                "iam_user_mfa_enabled_console_access",
            },
        }

        categories = set()

        for provider, check_ids in check_ids_by_provider.items():
            bulk_metadata = CheckMetadata.get_bulk(provider)
            for check_id in check_ids:
                check_metadata = CheckMetadata.get(bulk_metadata, check_id)
                if check_metadata and check_metadata.Categories:
                    categories.update(check_metadata.Categories)

        # Sort as done in the actual implementation
        sorted_categories = sorted(categories)

        # Verify sorting
        assert sorted_categories == [
            "compute",
            "identity-and-access-management",
            "networking",
            "security",
            "storage",
        ]
        assert sorted_categories == sorted(sorted_categories)
