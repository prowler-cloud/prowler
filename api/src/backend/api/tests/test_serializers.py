import pytest
from rest_framework.exceptions import ValidationError

from api.v1.serializer_utils.integrations import S3ConfigSerializer
from api.v1.serializers import ImageProviderSecret


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
