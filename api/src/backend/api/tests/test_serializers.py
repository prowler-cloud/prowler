from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel
from rest_framework.exceptions import ValidationError

from api.v1.serializer_utils.integrations import S3ConfigSerializer
from api.v1.serializers import (
    BaseWriteProviderSecretSerializer,
    ImageProviderSecret,
    ProviderEnumSerializerField,
)


class TestExternalProviderSecretValidation:
    """A non-built-in provider's secret is validated against the credential
    schema it declares through the SDK contract, or accepted as-is when it
    declares none (then validated by the provider's test_connection)."""

    class _Credentials(BaseModel):
        api_url: str
        api_key: str

    def test_secret_validated_against_declared_schema(self):
        provider_class = MagicMock()
        provider_class.get_credentials_schema.return_value = [self._Credentials]
        with patch(
            "api.v1.serializers.SDKProvider.get_class", return_value=provider_class
        ):
            BaseWriteProviderSecretSerializer._validate_external_provider_secret(
                "external-template", {"api_url": "u", "api_key": "k"}
            )

    def test_secret_rejected_when_schema_violated(self):
        provider_class = MagicMock()
        provider_class.get_credentials_schema.return_value = [self._Credentials]
        with patch(
            "api.v1.serializers.SDKProvider.get_class", return_value=provider_class
        ):
            with pytest.raises(ValidationError):
                BaseWriteProviderSecretSerializer._validate_external_provider_secret(
                    "external-template", {"api_url": "u"}
                )

    def test_secret_accepted_when_no_schema_declared(self):
        provider_class = MagicMock()
        provider_class.get_credentials_schema.return_value = []
        with patch(
            "api.v1.serializers.SDKProvider.get_class", return_value=provider_class
        ):
            BaseWriteProviderSecretSerializer._validate_external_provider_secret(
                "external-template", {"anything": "goes"}
            )

    @pytest.mark.parametrize("bad_secret", [["a", "b"], "a-string", None, 42])
    def test_secret_rejected_when_not_a_json_object(self, bad_secret):
        """Even with no declared schema, a non-object secret must be rejected so
        a list/string/null cannot be persisted and blow up later at
        ``{**secret}``. See PR #11402 review (Alan-TheGentleman)."""
        provider_class = MagicMock()
        provider_class.get_credentials_schema.return_value = []
        with patch(
            "api.v1.serializers.SDKProvider.get_class", return_value=provider_class
        ):
            with pytest.raises(ValidationError):
                BaseWriteProviderSecretSerializer._validate_external_provider_secret(
                    "external-template", bad_secret
                )


class TestProviderEnumSerializerField:
    """The provider field accepts whatever the SDK exposes (built-in or
    external) and rejects anything else with `invalid_choice`."""

    def test_accepts_sdk_available_provider(self):
        field = ProviderEnumSerializerField()
        assert field.run_validation("aws") == "aws"

    def test_accepts_external_provider_absent_from_static_enum(self):
        field = ProviderEnumSerializerField()
        # `llm` is exposed by the SDK but is not part of the legacy static enum.
        assert field.run_validation("llm") == "llm"

    def test_rejects_unknown_provider(self):
        field = ProviderEnumSerializerField()
        with pytest.raises(ValidationError) as exc:
            field.run_validation("does-not-exist")
        assert exc.value.detail[0].code == "invalid_choice"


class TestS3ConfigSerializer:
    """Test cases for S3ConfigSerializer validation."""

    def test_validate_output_directory_valid_paths(self):
        """Test that valid output directory paths are accepted."""
        serializer = S3ConfigSerializer()

        # Test normal paths
        assert serializer.validate_output_directory("test") == "test"
        assert serializer.validate_output_directory("test/folder") == "test/folder"
        assert serializer.validate_output_directory("my-folder_123") == "my-folder_123"

        # Test paths with leading slashes (should be normalized)
        assert serializer.validate_output_directory("/test") == "test"
        assert serializer.validate_output_directory("/test/folder") == "test/folder"

        # Test paths with excessive slashes (should be normalized)
        assert serializer.validate_output_directory("///test") == "test"
        assert serializer.validate_output_directory("///////test") == "test"
        assert serializer.validate_output_directory("test//folder") == "test/folder"
        assert serializer.validate_output_directory("test///folder") == "test/folder"

    def test_validate_output_directory_empty_values(self):
        """Test that empty values raise validation errors."""
        serializer = S3ConfigSerializer()

        with pytest.raises(
            ValidationError, match="Output directory cannot be empty or just"
        ):
            serializer.validate_output_directory(".")

        with pytest.raises(
            ValidationError, match="Output directory cannot be empty or just"
        ):
            serializer.validate_output_directory("/")

    def test_validate_output_directory_invalid_characters(self):
        """Test that invalid characters are rejected."""
        serializer = S3ConfigSerializer()

        invalid_chars = ["<", ">", ":", '"', "|", "?", "*"]

        for char in invalid_chars:
            with pytest.raises(
                ValidationError, match="Output directory contains invalid characters"
            ):
                serializer.validate_output_directory(f"test{char}folder")

    def test_validate_output_directory_too_long(self):
        """Test that paths that are too long are rejected."""
        serializer = S3ConfigSerializer()

        # Create a path longer than 900 characters
        long_path = "a" * 901

        with pytest.raises(ValidationError, match="Output directory path is too long"):
            serializer.validate_output_directory(long_path)

    def test_validate_output_directory_edge_cases(self):
        """Test edge cases for output directory validation."""
        serializer = S3ConfigSerializer()

        # Test path at the limit (900 characters)
        path_at_limit = "a" * 900
        assert serializer.validate_output_directory(path_at_limit) == path_at_limit

        # Test complex normalization
        assert serializer.validate_output_directory("//test/../folder//") == "folder"
        assert serializer.validate_output_directory("/test/./folder/") == "test/folder"

    def test_s3_config_serializer_full_validation(self):
        """Test the full S3ConfigSerializer with valid data."""
        data = {
            "bucket_name": "my-test-bucket",
            "output_directory": "///////test",  # This should be normalized
        }

        serializer = S3ConfigSerializer(data=data)
        assert serializer.is_valid()

        validated_data = serializer.validated_data
        assert validated_data["bucket_name"] == "my-test-bucket"
        assert validated_data["output_directory"] == "test"  # Normalized

    def test_s3_config_serializer_invalid_data(self):
        """Test the full S3ConfigSerializer with invalid data."""
        data = {
            "bucket_name": "my-test-bucket",
            "output_directory": "test<invalid",  # Contains invalid character
        }

        serializer = S3ConfigSerializer(data=data)
        assert not serializer.is_valid()
        assert "output_directory" in serializer.errors


class TestImageProviderSecret:
    """Test cases for ImageProviderSecret validation."""

    def test_valid_no_credentials(self):
        serializer = ImageProviderSecret(data={})
        assert serializer.is_valid()

    def test_valid_token_only(self):
        serializer = ImageProviderSecret(data={"registry_token": "tok"})
        assert serializer.is_valid()

    def test_valid_username_and_password(self):
        serializer = ImageProviderSecret(
            data={"registry_username": "user", "registry_password": "pass"}
        )
        assert serializer.is_valid()

    def test_valid_token_with_username_only(self):
        serializer = ImageProviderSecret(
            data={"registry_token": "tok", "registry_username": "user"}
        )
        assert serializer.is_valid()

    def test_invalid_username_without_password(self):
        serializer = ImageProviderSecret(data={"registry_username": "user"})
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_invalid_password_without_username(self):
        serializer = ImageProviderSecret(data={"registry_password": "pass"})
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors
