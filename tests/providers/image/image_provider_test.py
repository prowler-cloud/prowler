import os
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import CheckReportImage
from prowler.providers.image.exceptions.exceptions import (
    ImageInvalidConfigScannerError,
    ImageInvalidNameError,
    ImageInvalidScannerError,
    ImageInvalidSeverityError,
    ImageInvalidTimeoutError,
    ImageListFileNotFoundError,
    ImageListFileReadError,
    ImageNoImagesProvidedError,
    ImageRegistryAuthError,
    ImageScanError,
    ImageTrivyBinaryNotFoundError,
)
from prowler.providers.image.image_provider import ImageProvider
from tests.providers.image.image_fixtures import (
    SAMPLE_IMAGE_SHA,
    SAMPLE_MISCONFIGURATION_FINDING,
    SAMPLE_SECRET_FINDING,
    SAMPLE_UNKNOWN_SEVERITY_FINDING,
    SAMPLE_VULNERABILITY_FINDING,
    get_empty_trivy_output,
    get_invalid_trivy_output,
    get_multi_type_trivy_output,
    get_no_metadata_trivy_output,
    get_repo_digest_only_trivy_output,
    get_sample_trivy_json_output,
)


def _make_provider(**kwargs):
    """Helper to create an ImageProvider with test defaults."""
    defaults = {
        "images": ["alpine:3.18"],
        "config_content": {},
    }
    defaults.update(kwargs)
    return ImageProvider(**defaults)


class TestImageProvider:
    def test_image_provider(self):
        """Test default initialization."""
        provider = _make_provider()

        assert provider._type == "image"
        assert provider.type == "image"
        assert provider.images == ["alpine:3.18"]
        assert provider.scanners == ["vuln", "secret"]
        assert provider.image_config_scanners == []
        assert provider.trivy_severity == []
        assert provider.ignore_unfixed is False
        assert provider.timeout == "5m"
        assert provider.region == "container"
        assert provider.audited_account == "image-scan"
        assert provider.identity == "prowler"
        assert provider.auth_method == "No auth"
        assert provider.session is None
        assert provider.audit_config == {}
        assert provider.fixer_config == {}
        assert provider._mutelist is None

    def test_image_provider_custom_params(self):
        """Test initialization with custom parameters."""
        provider = _make_provider(
            images=["nginx:1.25", "redis:7"],
            scanners=["vuln", "secret", "misconfig"],
            trivy_severity=["HIGH", "CRITICAL"],
            ignore_unfixed=True,
            timeout="10m",
            fixer_config={"key": "value"},
        )

        assert provider.images == ["nginx:1.25", "redis:7"]
        assert provider.scanners == ["vuln", "secret", "misconfig"]
        assert provider.trivy_severity == ["HIGH", "CRITICAL"]
        assert provider.ignore_unfixed is True
        assert provider.timeout == "10m"
        assert provider.fixer_config == {"key": "value"}

    def test_image_provider_with_image_list_file(self):
        """Test loading images from a file, skipping comments and blank lines."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Comment line\n")
            f.write("alpine:3.18\n")
            f.write("\n")
            f.write("  nginx:latest  \n")
            f.write("# Another comment\n")
            f.write("redis:7\n")
            f.name

        provider = _make_provider(
            images=None,
            image_list_file=f.name,
        )

        assert "alpine:3.18" in provider.images
        assert "nginx:latest" in provider.images
        assert "redis:7" in provider.images
        assert len(provider.images) == 3

    def test_image_provider_no_images(self):
        """Test that ImageNoImagesProvidedError is raised when no images are given."""
        with pytest.raises(ImageNoImagesProvidedError):
            _make_provider(images=[])

    def test_image_provider_image_list_file_not_found(self):
        """Test that ImageListFileNotFoundError is raised for missing file."""
        with pytest.raises(ImageListFileNotFoundError):
            _make_provider(
                images=None,
                image_list_file="/nonexistent/path/images.txt",
            )

    def test_process_finding_vulnerability(self):
        """Test processing a vulnerability finding."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_VULNERABILITY_FINDING,
            "alpine:3.18",
            "alpine:3.18 (alpine 3.18.0)",
            image_sha="c1aabb73d233",
        )

        assert isinstance(report, CheckReportImage)
        assert report.status == "FAIL"
        assert report.check_metadata.CheckID == "CVE-2024-1234"
        assert report.check_metadata.Severity == "high"
        assert report.check_metadata.ServiceName == "container-image"
        assert report.check_metadata.ResourceType == "container-image"
        assert report.check_metadata.ResourceGroup == "container"
        assert report.package_name == "openssl"
        assert report.installed_version == "1.1.1k-r0"
        assert report.fixed_version == "1.1.1l-r0"
        assert report.resource_name == "alpine:3.18"
        assert report.image_sha == "c1aabb73d233"
        assert report.resource_details == "alpine:3.18 (alpine 3.18.0)"
        assert report.region == "container"
        assert report.check_metadata.Categories == ["vulnerability"]
        assert report.check_metadata.RelatedUrl == ""

    def test_process_finding_secret(self):
        """Test processing a secret finding (identified by RuleID)."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_SECRET_FINDING,
            "myimage:latest",
            "myimage:latest (debian 12)",
        )

        assert isinstance(report, CheckReportImage)
        assert report.status == "FAIL"
        assert report.check_metadata.CheckID == "aws-access-key-id"
        assert report.check_metadata.Severity == "critical"
        assert report.check_metadata.ServiceName == "container-image"
        assert report.check_metadata.Categories == ["secrets"]

    def test_process_finding_misconfiguration(self):
        """Test processing a misconfiguration finding (identified by ID)."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_MISCONFIGURATION_FINDING,
            "myimage:latest",
            "myimage:latest (debian 12)",
        )

        assert isinstance(report, CheckReportImage)
        assert report.check_metadata.CheckID == "DS001"
        assert report.check_metadata.Severity == "medium"
        assert report.check_metadata.ServiceName == "container-image"
        assert report.check_metadata.Categories == []

    def test_process_finding_unknown_severity(self):
        """Test that UNKNOWN severity is mapped to informational."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_UNKNOWN_SEVERITY_FINDING,
            "myimage:latest",
            "myimage:latest (alpine 3.18.0)",
        )

        assert report.check_metadata.Severity == "informational"

    @patch("subprocess.run")
    def test_run_scan_success(self, mock_subprocess):
        """Test successful scan with mocked subprocess."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert len(reports) == 1
        assert reports[0].check_metadata.CheckID == "CVE-2024-1234"
        assert reports[0].image_sha == SAMPLE_IMAGE_SHA
        assert reports[0].resource_name == "alpine:3.18"
        assert reports[0].check_metadata.ServiceName == "container-image"

    @patch("subprocess.run")
    def test_run_scan_empty_output(self, mock_subprocess):
        """Test scan with empty Trivy output produces no findings."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_empty_trivy_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert len(reports) == 0

    @patch("subprocess.run")
    def test_run_scan_invalid_json(self, mock_subprocess):
        """Test scan with malformed output doesn't crash."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_invalid_trivy_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert len(reports) == 0

    @patch("subprocess.run")
    def test_run_scan_trivy_not_found(self, mock_subprocess):
        """Test that ImageTrivyBinaryNotFoundError is raised when trivy is missing."""
        provider = _make_provider()
        mock_subprocess.side_effect = FileNotFoundError(
            "[Errno 2] No such file or directory: 'trivy'"
        )

        with pytest.raises(ImageTrivyBinaryNotFoundError):
            for _ in provider._scan_single_image("alpine:3.18"):
                pass

    @patch("subprocess.run")
    def test_run_scan_multiple_images(self, mock_subprocess):
        """Test scanning multiple images makes separate subprocess calls."""
        provider = _make_provider(images=["alpine:3.18", "nginx:latest"])
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert mock_subprocess.call_count == 2

    @patch("subprocess.run")
    def test_run_scan_multi_type_output(self, mock_subprocess):
        """Test scan with vulnerabilities, secrets, and misconfigurations."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_multi_type_trivy_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert len(reports) == 3

        check_ids = [r.check_metadata.CheckID for r in reports]
        assert "CVE-2024-1234" in check_ids
        assert "aws-access-key-id" in check_ids
        assert "DS001" in check_ids

    def test_print_credentials(self):
        """Test that print_credentials outputs image names."""
        provider = _make_provider()
        with mock.patch("builtins.print") as mock_print:
            provider.print_credentials()
            output = " ".join(
                str(call.args[0]) for call in mock_print.call_args_list if call.args
            )
            assert "alpine:3.18" in output

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_success(self, mock_factory):
        """Test successful connection returns is_connected=True."""
        mock_adapter = MagicMock()
        mock_adapter.list_tags.return_value = ["3.18", "latest"]
        mock_factory.return_value = mock_adapter

        result = ImageProvider.test_connection(image="alpine:3.18")

        assert result.is_connected is True
        mock_adapter.list_tags.assert_called_once_with("library/alpine")

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_auth_failure(self, mock_factory):
        """Test registry auth error returns auth failure."""
        mock_factory.return_value = MagicMock(
            list_tags=MagicMock(side_effect=ImageRegistryAuthError(file=__file__))
        )

        result = ImageProvider.test_connection(image="private/image:latest")

        assert result.is_connected is False
        assert "Authentication failed" in result.error

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_not_found(self, mock_factory):
        """Test tag not found returns not found error."""
        mock_adapter = MagicMock()
        mock_adapter.list_tags.return_value = ["v1", "v2"]
        mock_factory.return_value = mock_adapter

        result = ImageProvider.test_connection(image="nonexistent/image:latest")

        assert result.is_connected is False
        assert "not found" in result.error

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_registry_url(self, mock_factory):
        """Test registry URL (namespace) uses list_repositories."""
        mock_adapter = MagicMock()
        mock_adapter.list_repositories.return_value = ["andoniaf/myapp"]
        mock_factory.return_value = mock_adapter

        result = ImageProvider.test_connection(image="docker.io/andoniaf")

        assert result.is_connected is True
        mock_factory.assert_called_once_with(
            registry_url="docker.io/andoniaf",
            username=None,
            password=None,
            token=None,
        )
        mock_adapter.list_repositories.assert_called_once()

    def test_build_status_extended(self):
        """Test status message content for different finding types."""
        provider = _make_provider()

        # Vulnerability with fix
        status = provider._build_status_extended(SAMPLE_VULNERABILITY_FINDING)
        assert "CVE-2024-1234" in status
        assert "openssl" in status
        assert "fix available" in status

        # Finding with no special fields
        status = provider._build_status_extended({"Description": "Simple finding"})
        assert status == "Simple finding"

        # Finding with will_not_fix status
        finding_no_fix = {
            "VulnerabilityID": "CVE-2024-0000",
            "PkgName": "libc",
            "Status": "will_not_fix",
            "Title": "Some vuln",
        }
        status = provider._build_status_extended(finding_no_fix)
        assert "no fix available" in status

    def test_validate_arguments(self):
        """Test valid and invalid argument combinations."""
        # Valid: images provided
        provider = _make_provider(images=["alpine:3.18"])
        assert provider.images == ["alpine:3.18"]

        # Invalid: empty images and no file
        with pytest.raises(ImageNoImagesProvidedError):
            _make_provider(images=[])

        # Valid: custom scanners
        provider = _make_provider(scanners=["vuln"])
        assert provider.scanners == ["vuln"]

    def test_setup_session(self):
        """Test that setup_session returns None."""
        provider = _make_provider()
        assert provider.setup_session() is None

    @patch("subprocess.run")
    def test_run_method(self, mock_subprocess):
        """Test that run() collects all batches into a list."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = provider.run()

        assert isinstance(reports, list)
        assert len(reports) == 1

    @patch("subprocess.run")
    def test_scan_single_image_trivy_nonzero_exit(self, mock_subprocess):
        """Test that a non-zero Trivy exit code raises ImageScanError."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="fatal error: unable to pull image",
        )

        with pytest.raises(ImageScanError):
            for _ in provider._scan_single_image("alpine:3.18"):
                pass

    @patch("subprocess.run")
    def test_scan_single_image_auth_failure(self, mock_subprocess):
        """Test that a 401 unauthorized stderr raises ImageScanError with message."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="ERROR 401 unauthorized: authentication required",
        )

        with pytest.raises(ImageScanError, match="401 unauthorized"):
            for _ in provider._scan_single_image("private/image:latest"):
                pass

    @patch("subprocess.run")
    def test_sha_extraction_from_image_id(self, mock_subprocess):
        """Test that image_sha is extracted from Trivy Metadata.ImageID."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = []
        for batch in provider._scan_single_image("alpine:3.18"):
            reports.extend(batch)

        assert len(reports) == 1
        assert reports[0].image_sha == SAMPLE_IMAGE_SHA

    @patch("subprocess.run")
    def test_sha_extraction_fallback_to_repo_digests(self, mock_subprocess):
        """Test that image_sha falls back to RepoDigests when ImageID is absent."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_repo_digest_only_trivy_output(), stderr=""
        )

        reports = []
        for batch in provider._scan_single_image("alpine:3.18"):
            reports.extend(batch)

        assert len(reports) == 1
        assert reports[0].image_sha == "e5f6g7h8i9j0"

    @patch("subprocess.run")
    def test_sha_extraction_no_metadata(self, mock_subprocess):
        """Test that image_sha is empty when no Metadata is present."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_no_metadata_trivy_output(), stderr=""
        )

        reports = []
        for batch in provider._scan_single_image("alpine:3.18"):
            reports.extend(batch)

        assert len(reports) == 1
        assert reports[0].image_sha == ""

    @patch("subprocess.run")
    def test_run_scan_propagates_scan_error(self, mock_subprocess):
        """Test that run_scan() re-raises ImageScanError instead of swallowing it."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="image not found",
        )

        with pytest.raises(ImageScanError):
            for _ in provider.run_scan():
                pass


class TestImageProviderRegistryAuth:
    def test_no_auth_by_default(self):
        """Test that no auth is set when no credentials are provided."""
        provider = _make_provider()

        assert provider.registry_username is None
        assert provider.registry_password is None
        assert provider.registry_token is None
        assert provider.auth_method == "No auth"

    def test_basic_auth_with_explicit_params(self):
        """Test basic auth via explicit constructor params."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
        )

        assert provider.registry_username == "myuser"
        assert provider.registry_password == "mypass"
        assert provider.auth_method == "Docker login"

    def test_token_auth_with_explicit_param(self):
        """Test token auth via explicit constructor param."""
        provider = _make_provider(registry_token="my-token-123")

        assert provider.registry_token == "my-token-123"
        assert provider.auth_method == "Registry token"

    def test_basic_auth_takes_precedence_over_token(self):
        """Test that username/password takes precedence over token."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
            registry_token="my-token",
        )

        assert provider.auth_method == "Docker login"

    @patch.dict(
        os.environ, {"REGISTRY_USERNAME": "envuser", "REGISTRY_PASSWORD": "envpass"}
    )
    def test_basic_auth_from_env_vars(self):
        """Test that env vars are used as fallback for basic auth."""
        provider = _make_provider()

        assert provider.registry_username == "envuser"
        assert provider.registry_password == "envpass"
        assert provider.auth_method == "Docker login"

    @patch.dict(os.environ, {"REGISTRY_TOKEN": "env-token"})
    def test_token_auth_from_env_var(self):
        """Test that env var is used as fallback for token auth."""
        provider = _make_provider()

        assert provider.registry_token == "env-token"
        assert provider.auth_method == "Registry token"

    @patch.dict(
        os.environ, {"REGISTRY_USERNAME": "envuser", "REGISTRY_PASSWORD": "envpass"}
    )
    def test_explicit_params_override_env_vars(self):
        """Test that explicit params take precedence over env vars."""
        provider = _make_provider(
            registry_username="explicit",
            registry_password="explicit-pass",
        )

        assert provider.registry_username == "explicit"
        assert provider.registry_password == "explicit-pass"

    def test_build_trivy_env_no_auth(self):
        """Test that _build_trivy_env returns base env when no auth."""
        provider = _make_provider()
        env = provider._build_trivy_env()

        assert "TRIVY_USERNAME" not in env
        assert "TRIVY_PASSWORD" not in env
        assert "TRIVY_REGISTRY_TOKEN" not in env

    def test_build_trivy_env_basic_auth_sets_env_vars(self):
        """Test that _build_trivy_env injects TRIVY_USERNAME/PASSWORD for native Trivy auth."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
        )
        env = provider._build_trivy_env()

        assert env["TRIVY_USERNAME"] == "myuser"
        assert env["TRIVY_PASSWORD"] == "mypass"

    def test_build_trivy_env_token_auth(self):
        """Test that _build_trivy_env injects registry token."""
        provider = _make_provider(registry_token="my-token")
        env = provider._build_trivy_env()

        assert env["TRIVY_REGISTRY_TOKEN"] == "my-token"

    @patch("subprocess.run")
    def test_execute_trivy_sets_trivy_env_with_basic_auth(self, mock_subprocess):
        """Test that _execute_trivy sets TRIVY_USERNAME/PASSWORD for native Trivy auth."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
        )
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )

        provider._execute_trivy(["trivy", "image", "alpine:3.18"], "alpine:3.18")

        call_kwargs = mock_subprocess.call_args
        env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert env["TRIVY_USERNAME"] == "myuser"
        assert env["TRIVY_PASSWORD"] == "mypass"

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_with_basic_auth(self, mock_factory):
        """Test test_connection passes credentials to the registry adapter."""
        mock_adapter = MagicMock()
        mock_adapter.list_tags.return_value = ["v1"]
        mock_factory.return_value = mock_adapter

        result = ImageProvider.test_connection(
            image="private.registry.io/myapp:v1",
            registry_username="myuser",
            registry_password="mypass",
        )

        assert result.is_connected is True
        mock_factory.assert_called_once_with(
            registry_url="private.registry.io",
            username="myuser",
            password="mypass",
            token=None,
        )

    @patch("prowler.providers.image.image_provider.create_registry_adapter")
    def test_test_connection_with_token(self, mock_factory):
        """Test test_connection passes token to the registry adapter."""
        mock_adapter = MagicMock()
        mock_adapter.list_tags.return_value = ["v1"]
        mock_factory.return_value = mock_adapter

        result = ImageProvider.test_connection(
            image="private.registry.io/myapp:v1",
            registry_token="my-token",
        )

        assert result.is_connected is True
        mock_factory.assert_called_once_with(
            registry_url="private.registry.io",
            username=None,
            password=None,
            token="my-token",
        )

    def test_print_credentials_shows_auth_method(self):
        """Test that print_credentials outputs the auth method."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
        )
        with mock.patch("builtins.print") as mock_print:
            provider.print_credentials()
            output = " ".join(
                str(call.args[0]) for call in mock_print.call_args_list if call.args
            )
            assert "Docker login" in output


class TestExtractRegistry:
    def test_docker_hub_simple(self):
        assert ImageProvider._extract_registry("alpine:3.18") is None

    def test_docker_hub_with_namespace(self):
        assert ImageProvider._extract_registry("andoniaf/test-private:tag") is None

    def test_ghcr(self):
        assert ImageProvider._extract_registry("ghcr.io/user/image:tag") == "ghcr.io"

    def test_ecr(self):
        assert (
            ImageProvider._extract_registry(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag"
            )
            == "123456789012.dkr.ecr.us-east-1.amazonaws.com"
        )

    def test_localhost_with_port(self):
        assert (
            ImageProvider._extract_registry("localhost:5000/myimage:latest")
            == "localhost:5000"
        )

    def test_custom_registry_with_port(self):
        assert (
            ImageProvider._extract_registry("myregistry.io:5000/image:tag")
            == "myregistry.io:5000"
        )

    def test_digest_reference(self):
        assert (
            ImageProvider._extract_registry("ghcr.io/user/image@sha256:abc123")
            == "ghcr.io"
        )

    def test_bare_image_name(self):
        assert ImageProvider._extract_registry("nginx") is None


class TestIsRegistryUrl:
    def test_registry_url_with_namespace(self):
        assert ImageProvider._is_registry_url("docker.io/andoniaf") is True

    def test_registry_url_ghcr(self):
        assert ImageProvider._is_registry_url("ghcr.io/org") is True

    def test_image_ref_with_tag(self):
        assert ImageProvider._is_registry_url("ghcr.io/user/image:tag") is False

    def test_image_ref_with_repo(self):
        assert ImageProvider._is_registry_url("ghcr.io/user/image") is False

    def test_dockerhub_short_image(self):
        assert ImageProvider._is_registry_url("alpine:3.18") is False

    def test_dockerhub_with_namespace(self):
        assert ImageProvider._is_registry_url("andoniaf/test:tag") is False

    def test_bare_image_name(self):
        assert ImageProvider._is_registry_url("nginx") is False

    def test_localhost_namespace(self):
        assert ImageProvider._is_registry_url("localhost:5000/myns") is True

    def test_localhost_image_with_tag(self):
        assert ImageProvider._is_registry_url("localhost:5000/myns/image:v1") is False


class TestCleanup:
    def test_cleanup_idempotent(self):
        """Test cleanup is safe to call multiple times."""
        provider = _make_provider()

        provider.cleanup()
        provider.cleanup()


class TestImageProviderInputValidation:
    def test_invalid_timeout_format_raises_error(self):
        """Test that a non-matching timeout string raises ImageInvalidTimeoutError."""
        with pytest.raises(ImageInvalidTimeoutError):
            _make_provider(timeout="invalid")

    def test_invalid_timeout_no_unit_raises_error(self):
        """Test that a numeric timeout without a unit raises ImageInvalidTimeoutError."""
        with pytest.raises(ImageInvalidTimeoutError):
            _make_provider(timeout="300")

    def test_invalid_timeout_wrong_unit_raises_error(self):
        """Test that a timeout with an unsupported unit raises ImageInvalidTimeoutError."""
        with pytest.raises(ImageInvalidTimeoutError):
            _make_provider(timeout="5d")

    def test_valid_timeout_seconds(self):
        """Test that a seconds-based timeout is accepted."""
        provider = _make_provider(timeout="300s")
        assert provider.timeout == "300s"

    def test_valid_timeout_hours(self):
        """Test that an hours-based timeout is accepted."""
        provider = _make_provider(timeout="1h")
        assert provider.timeout == "1h"

    def test_invalid_scanner_raises_error(self):
        """Test that an invalid scanner name raises ImageInvalidScannerError."""
        with pytest.raises(ImageInvalidScannerError):
            _make_provider(scanners=["vuln", "bad"])

    def test_invalid_severity_raises_error(self):
        """Test that an invalid severity level raises ImageInvalidSeverityError."""
        with pytest.raises(ImageInvalidSeverityError):
            _make_provider(trivy_severity=["HIGH", "SUPER_HIGH"])

    def test_valid_all_scanners(self):
        """Test that all valid scanner choices are accepted."""
        provider = _make_provider(scanners=["vuln", "secret", "misconfig", "license"])
        assert provider.scanners == ["vuln", "secret", "misconfig", "license"]

    def test_valid_all_severities(self):
        """Test that all valid severity choices are accepted."""
        provider = _make_provider(
            trivy_severity=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        )
        assert provider.trivy_severity == [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
        ]

    def test_image_config_scanners_defaults_to_empty(self):
        """Test that image_config_scanners defaults to an empty list."""
        provider = _make_provider()
        assert provider.image_config_scanners == []

    def test_valid_image_config_scanners(self):
        """Test that valid image config scanners are accepted."""
        provider = _make_provider(image_config_scanners=["misconfig", "secret"])
        assert provider.image_config_scanners == ["misconfig", "secret"]

    def test_invalid_image_config_scanner_raises_error(self):
        """Test that an invalid image config scanner raises ImageInvalidConfigScannerError."""
        with pytest.raises(ImageInvalidConfigScannerError):
            _make_provider(image_config_scanners=["misconfig", "vuln"])

    @patch("subprocess.run")
    def test_trivy_command_includes_image_config_scanners(self, mock_subprocess):
        """Test that Trivy command includes --image-config-scanners when set."""
        provider = _make_provider(image_config_scanners=["misconfig", "secret"])
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_empty_trivy_output(), stderr=""
        )

        for _ in provider._scan_single_image("alpine:3.18"):
            pass

        call_args = mock_subprocess.call_args[0][0]
        assert "--image-config-scanners" in call_args
        idx = call_args.index("--image-config-scanners")
        assert call_args[idx + 1] == "misconfig,secret"

    @patch("subprocess.run")
    def test_trivy_command_omits_image_config_scanners_when_empty(
        self, mock_subprocess
    ):
        """Test that Trivy command omits --image-config-scanners when empty."""
        provider = _make_provider(image_config_scanners=[])
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_empty_trivy_output(), stderr=""
        )

        for _ in provider._scan_single_image("alpine:3.18"):
            pass

        call_args = mock_subprocess.call_args[0][0]
        assert "--image-config-scanners" not in call_args


class TestImageProviderErrorCategorization:
    def test_categorize_auth_failure(self):
        """Test that auth-related errors are categorized correctly."""
        result = ImageProvider._categorize_trivy_error(
            "401 unauthorized: access denied"
        )
        assert "Auth failure" in result

    def test_categorize_not_found(self):
        """Test that not-found errors are categorized correctly."""
        result = ImageProvider._categorize_trivy_error(
            "manifest unknown: image not found"
        )
        assert "Image not found" in result

    def test_categorize_rate_limit(self):
        """Test that rate-limit errors are categorized correctly."""
        result = ImageProvider._categorize_trivy_error("429 too many requests")
        assert "Rate limited" in result

    def test_categorize_network_issue(self):
        """Test that network errors are categorized correctly."""
        result = ImageProvider._categorize_trivy_error("connection refused to registry")
        assert "Network issue" in result

    def test_categorize_unknown_error(self):
        """Test that unrecognized errors are returned as-is."""
        msg = "some unknown trivy error"
        result = ImageProvider._categorize_trivy_error(msg)
        assert result == msg


class TestImageProviderNameValidation:
    @pytest.mark.parametrize(
        "bad_name",
        [
            "alpine;rm -rf /",
            "image|cat /etc/passwd",
            "image&background",
            "image$VAR",
            "image`whoami`",
            "image\ninjected",
            "image\rinjected",
        ],
    )
    def test_image_provider_invalid_image_name_shell_chars(self, bad_name):
        """Test that image names with shell metacharacters raise ImageInvalidNameError."""
        with pytest.raises(ImageInvalidNameError):
            _make_provider(images=[bad_name])

    def test_image_provider_invalid_image_name_empty(self):
        """Test that an empty string image name raises ImageInvalidNameError."""
        with pytest.raises(ImageInvalidNameError):
            _make_provider(images=[""])

    @pytest.mark.parametrize(
        "valid_name",
        [
            "alpine:3.18",
            "nginx:latest",
            "registry.example.com/repo/image:tag",
            "ghcr.io/owner/image:v1.2.3",
            "myimage@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "localhost:5000/myimage:latest",
        ],
    )
    def test_image_provider_valid_image_names(self, valid_name):
        """Test that various valid image name formats pass validation."""
        provider = _make_provider(images=[valid_name])
        assert valid_name in provider.images

    def test_image_provider_image_name_too_long(self):
        """Test that a name exceeding 500 chars raises ImageInvalidNameError."""
        long_name = "a" * 501
        with pytest.raises(ImageInvalidNameError):
            _make_provider(images=[long_name])

    def test_image_provider_file_too_many_lines(self):
        """Test that a file with more than MAX_IMAGE_LIST_LINES raises ImageListFileReadError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for i in range(10_001):
                f.write(f"image{i}:latest\n")
            f.flush()
            file_path = f.name

        with pytest.raises(ImageListFileReadError):
            _make_provider(images=None, image_list_file=file_path)


class TestScanPerImage:
    @patch("subprocess.run")
    def test_yields_per_image(self, mock_subprocess):
        """Test that scan_per_image yields (name, findings) per image."""
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )
        provider = _make_provider(images=["alpine:3.18", "nginx:latest"])

        results = list(provider.scan_per_image())

        assert len(results) == 2
        for name, findings in results:
            assert isinstance(name, str)
            assert isinstance(findings, list)
            assert all(isinstance(f, CheckReportImage) for f in findings)

    @patch("subprocess.run")
    def test_reraises_scan_error(self, mock_subprocess):
        """Test that ImageScanError propagates from scan_per_image."""
        mock_subprocess.return_value = MagicMock(
            returncode=1, stdout="", stderr="scan failed"
        )
        provider = _make_provider(images=["alpine:3.18"])

        with pytest.raises(ImageScanError):
            list(provider.scan_per_image())

    @patch("subprocess.run")
    def test_skips_generic_error(self, mock_subprocess):
        """Test that a generic RuntimeError in _scan_single_image yields empty findings and continues."""

        def side_effect(cmd, **kwargs):
            if "bad:image" in cmd:
                raise RuntimeError("unexpected error")
            return MagicMock(
                returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
            )

        mock_subprocess.side_effect = side_effect
        provider = _make_provider(images=["bad:image", "alpine:3.18"])

        results = list(provider.scan_per_image())

        assert len(results) == 2
        assert results[0][0] == "bad:image"
        assert results[0][1] == []
        assert results[1][0] == "alpine:3.18"
        assert len(results[1][1]) > 0

    @patch("subprocess.run")
    def test_calls_cleanup(self, mock_subprocess):
        """Test that cleanup is called even after scan_per_image completes."""
        mock_subprocess.return_value = MagicMock(
            returncode=0, stdout=get_sample_trivy_json_output(), stderr=""
        )
        provider = _make_provider(images=["alpine:3.18"])

        with mock.patch.object(provider, "cleanup") as mock_cleanup:
            list(provider.scan_per_image())

        mock_cleanup.assert_called_once()
