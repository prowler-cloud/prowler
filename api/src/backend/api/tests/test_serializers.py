import pytest
from api.v1.serializer_utils.integrations import (
    JiraCredentialSerializer,
    S3ConfigSerializer,
)
from api.v1.serializer_utils.providers import ProviderSecretField
from api.v1.serializers import (
    ImageProviderSecret,
    KubernetesProviderSecret,
    OracleCloudProviderSecret,
)
from rest_framework.exceptions import ValidationError


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


class TestJiraCredentialSerializer:
    @pytest.mark.parametrize(
        "domain",
        (
            "a",
            "prowler",
            "prowler-domain",
            "A1-b2-C3",
            "a" * 63,
        ),
    )
    def test_valid_site_name(self, domain):
        serializer = JiraCredentialSerializer(
            data={
                "user_mail": "testing@prowler.com",
                "api_token": "fake-api-token",
                "domain": domain,
            }
        )

        assert serializer.is_valid(), serializer.errors

    @pytest.mark.parametrize(
        "domain",
        (
            "169.254.169.254#",
            "internal/service",
            "internal?target",
            "internal\\target",
            "internal:8000",
            "user@internal",
            "example.atlassian.net",
            "-prowler",
            "prowler-",
            "a" * 64,
            " prowler",
            "prowler ",
            "prowler\n",
        ),
    )
    def test_invalid_site_name(self, domain):
        serializer = JiraCredentialSerializer(
            data={
                "user_mail": "testing@prowler.com",
                "api_token": "fake-api-token",
                "domain": domain,
            }
        )

        assert not serializer.is_valid()
        assert "domain" in serializer.errors


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


class TestOracleCloudProviderSecret:
    def valid_secret(self, **overrides):
        secret = {
            "user": "ocid1.user.oc1..aaaaaaaexample",
            "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
            "key_content": "fake-base64-key-content",
            "tenancy": "ocid1.tenancy.oc1..aaaaaaaexample",
        }
        secret.update(overrides)
        return secret

    def test_accepts_regionless_secret(self):
        serializer = OracleCloudProviderSecret(data=self.valid_secret())

        assert serializer.is_valid(), serializer.errors
        assert "region" not in serializer.validated_data

    def test_accepts_and_ignores_region_field(self):
        secret = self.valid_secret(region="us-phoenix-1")
        serializer = OracleCloudProviderSecret(data=secret)

        assert serializer.is_valid(), serializer.errors

        assert "region" not in serializer.validated_data

    @pytest.mark.parametrize(
        "legacy_field, legacy_value",
        [
            ("region", None),
            ("region", ""),
            ("region", {"name": "us-ashburn-1"}),
        ],
    )
    def test_accepts_and_ignores_any_legacy_region_value(
        self, legacy_field, legacy_value
    ):
        serializer = OracleCloudProviderSecret(
            data=self.valid_secret(**{legacy_field: legacy_value})
        )

        assert serializer.is_valid(), serializer.errors

        assert legacy_field not in serializer.validated_data


class TestProviderSecretFieldSchema:
    def test_oraclecloud_schema_includes_legacy_region_field(self):
        schema = ProviderSecretField._spectacular_annotation["field"]
        oraclecloud_schema = next(
            credential_schema
            for credential_schema in schema["oneOf"]
            if credential_schema["title"]
            == "Oracle Cloud Infrastructure (OCI) API Key Credentials"
        )

        assert oraclecloud_schema["properties"]["region"]["deprecated"] is True


class TestKubernetesProviderSecret:
    def test_valid_static_kubeconfig_is_accepted(self):
        kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
  - name: test-cluster
    cluster:
      server: https://kubernetes.example.test
users:
  - name: test-user
    user:
      token: test-token
contexts:
  - name: test-context
    context:
      cluster: test-cluster
      user: test-user
current-context: test-context
"""

        serializer = KubernetesProviderSecret(
            data={"kubeconfig_content": kubeconfig_content}
        )

        assert serializer.is_valid()

    def test_kubeconfig_with_exec_authentication_is_rejected(self):
        kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
  - name: test-cluster
    cluster:
      server: https://kubernetes.example.test
users:
  - name: test-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl
contexts:
  - name: test-context
    context:
      cluster: test-cluster
      user: test-user
current-context: test-context
"""

        serializer = KubernetesProviderSecret(
            data={"kubeconfig_content": kubeconfig_content}
        )

        assert not serializer.is_valid()
        assert "kubeconfig_content" in serializer.errors

    def test_kubeconfig_with_auth_provider_cmd_path_is_rejected(self):
        kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
  - name: test-cluster
    cluster:
      server: https://kubernetes.example.test
users:
  - name: test-user
    user:
      auth-provider:
        name: gcp
        config:
          cmd-path: /bin/sh
contexts:
  - name: test-context
    context:
      cluster: test-cluster
      user: test-user
current-context: test-context
"""

        serializer = KubernetesProviderSecret(
            data={"kubeconfig_content": kubeconfig_content}
        )

        assert not serializer.is_valid()
        assert "kubeconfig_content" in serializer.errors

    def test_malformed_kubeconfig_is_rejected(self):
        serializer = KubernetesProviderSecret(
            data={"kubeconfig_content": "apiVersion: ["}
        )

        assert not serializer.is_valid()
        assert "kubeconfig_content" in serializer.errors

    def test_non_mapping_kubeconfig_is_rejected(self):
        serializer = KubernetesProviderSecret(data={"kubeconfig_content": "[]"})

        assert not serializer.is_valid()
        assert "kubeconfig_content" in serializer.errors
