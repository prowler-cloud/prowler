import os
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import CheckReportImage
from prowler.providers.image.exceptions.exceptions import (
    ImageListFileNotFoundError,
    ImageNoImagesProvidedError,
    ImageTrivyBinaryNotFoundError,
)
from prowler.providers.image.image_provider import ImageProvider
from tests.providers.image.image_fixtures import (
    SAMPLE_MISCONFIGURATION_FINDING,
    SAMPLE_SECRET_FINDING,
    SAMPLE_UNKNOWN_SEVERITY_FINDING,
    SAMPLE_VULNERABILITY_FINDING,
    get_empty_trivy_output,
    get_invalid_trivy_output,
    get_multi_type_trivy_output,
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
            "alpine:3.18 (alpine 3.18.0)",
            "alpine",
        )

        assert isinstance(report, CheckReportImage)
        assert report.status == "FAIL"
        assert report.check_metadata.CheckID == "CVE-2024-1234"
        assert report.check_metadata.Severity == "high"
        assert report.check_metadata.ServiceName == "alpine"
        assert report.check_metadata.ResourceType == "container-image"
        assert report.check_metadata.ResourceGroup == "container"
        assert report.package_name == "openssl"
        assert report.installed_version == "1.1.1k-r0"
        assert report.fixed_version == "1.1.1l-r0"
        assert report.resource_name == "alpine:3.18 (alpine 3.18.0)"
        assert report.region == "container"

    def test_process_finding_secret(self):
        """Test processing a secret finding (identified by RuleID)."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_SECRET_FINDING,
            "myimage:latest",
            "secret",
        )

        assert isinstance(report, CheckReportImage)
        assert report.status == "FAIL"
        assert report.check_metadata.CheckID == "aws-access-key-id"
        assert report.check_metadata.Severity == "critical"
        assert report.check_metadata.ServiceName == "secret"

    def test_process_finding_misconfiguration(self):
        """Test processing a misconfiguration finding (identified by ID)."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_MISCONFIGURATION_FINDING,
            "myimage:latest",
            "misconfiguration",
        )

        assert isinstance(report, CheckReportImage)
        assert report.check_metadata.CheckID == "DS001"
        assert report.check_metadata.Severity == "medium"
        assert report.check_metadata.ServiceName == "misconfiguration"

    def test_process_finding_unknown_severity(self):
        """Test that UNKNOWN severity is mapped to informational."""
        provider = _make_provider()
        report = provider._process_finding(
            SAMPLE_UNKNOWN_SEVERITY_FINDING,
            "myimage:latest",
            "alpine",
        )

        assert report.check_metadata.Severity == "informational"

    @patch("subprocess.run")
    def test_run_scan_success(self, mock_subprocess):
        """Test successful scan with mocked subprocess."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = []
        for batch in provider.run_scan():
            reports.extend(batch)

        assert len(reports) == 1
        assert reports[0].check_metadata.CheckID == "CVE-2024-1234"

    @patch("subprocess.run")
    def test_run_scan_empty_output(self, mock_subprocess):
        """Test scan with empty Trivy output produces no findings."""
        provider = _make_provider()
        mock_subprocess.return_value = MagicMock(
            stdout=get_empty_trivy_output(), stderr=""
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
            stdout=get_invalid_trivy_output(), stderr=""
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
            stdout=get_sample_trivy_json_output(), stderr=""
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
            stdout=get_multi_type_trivy_output(), stderr=""
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

    @patch("subprocess.run")
    def test_test_connection_success(self, mock_subprocess):
        """Test successful connection returns is_connected=True."""
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")

        result = ImageProvider.test_connection(image="alpine:3.18")

        assert result.is_connected is True

    @patch("subprocess.run")
    def test_test_connection_auth_failure(self, mock_subprocess):
        """Test 401 error returns auth failure."""
        mock_subprocess.return_value = MagicMock(
            returncode=1, stderr="401 unauthorized"
        )

        result = ImageProvider.test_connection(image="private/image:latest")

        assert result.is_connected is False
        assert "Authentication failed" in result.error

    @patch("subprocess.run")
    def test_test_connection_not_found(self, mock_subprocess):
        """Test 404 error returns not found."""
        mock_subprocess.return_value = MagicMock(returncode=1, stderr="404 not found")

        result = ImageProvider.test_connection(image="nonexistent/image:latest")

        assert result.is_connected is False
        assert "not found" in result.error

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
            stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = provider.run()

        assert isinstance(reports, list)
        assert len(reports) == 1


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
        assert provider.auth_method == "Basic auth"

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

        assert provider.auth_method == "Basic auth"

    @patch.dict(os.environ, {"TRIVY_USERNAME": "envuser", "TRIVY_PASSWORD": "envpass"})
    def test_basic_auth_from_env_vars(self):
        """Test that env vars are used as fallback for basic auth."""
        provider = _make_provider()

        assert provider.registry_username == "envuser"
        assert provider.registry_password == "envpass"
        assert provider.auth_method == "Basic auth"

    @patch.dict(os.environ, {"TRIVY_REGISTRY_TOKEN": "env-token"})
    def test_token_auth_from_env_var(self):
        """Test that env var is used as fallback for token auth."""
        provider = _make_provider()

        assert provider.registry_token == "env-token"
        assert provider.auth_method == "Registry token"

    @patch.dict(os.environ, {"TRIVY_USERNAME": "envuser", "TRIVY_PASSWORD": "envpass"})
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

    def test_build_trivy_env_basic_auth(self):
        """Test that _build_trivy_env injects username/password."""
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
    def test_execute_trivy_passes_env(self, mock_subprocess):
        """Test that _execute_trivy passes credentials via env."""
        provider = _make_provider(
            registry_username="myuser",
            registry_password="mypass",
        )
        mock_subprocess.return_value = MagicMock(
            stdout=get_sample_trivy_json_output(), stderr=""
        )

        provider._execute_trivy(["trivy", "image", "alpine:3.18"], "alpine:3.18")

        call_kwargs = mock_subprocess.call_args
        env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert env["TRIVY_USERNAME"] == "myuser"
        assert env["TRIVY_PASSWORD"] == "mypass"

    @patch("subprocess.run")
    def test_test_connection_with_basic_auth(self, mock_subprocess):
        """Test test_connection passes credentials via env."""
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")

        result = ImageProvider.test_connection(
            image="private.registry.io/myapp:v1",
            registry_username="myuser",
            registry_password="mypass",
        )

        assert result.is_connected is True
        call_kwargs = mock_subprocess.call_args
        env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert env["TRIVY_USERNAME"] == "myuser"
        assert env["TRIVY_PASSWORD"] == "mypass"

    @patch("subprocess.run")
    def test_test_connection_with_token(self, mock_subprocess):
        """Test test_connection passes token via env."""
        mock_subprocess.return_value = MagicMock(returncode=0, stderr="")

        result = ImageProvider.test_connection(
            image="private.registry.io/myapp:v1",
            registry_token="my-token",
        )

        assert result.is_connected is True
        call_kwargs = mock_subprocess.call_args
        env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert env["TRIVY_REGISTRY_TOKEN"] == "my-token"

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
            assert "Basic auth" in output
