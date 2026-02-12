from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Generator

from alive_progress import alive_bar
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    load_and_validate_config_file,
)
from prowler.lib.check.models import CheckReportImage
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.image.exceptions.exceptions import (
    ImageFindingProcessingError,
    ImageInvalidConfigScannerError,
    ImageInvalidNameError,
    ImageInvalidScannerError,
    ImageInvalidSeverityError,
    ImageInvalidTimeoutError,
    ImageListFileNotFoundError,
    ImageListFileReadError,
    ImageNoImagesProvidedError,
    ImageScanError,
    ImageTrivyBinaryNotFoundError,
)
from prowler.providers.image.lib.arguments.arguments import (
    IMAGE_CONFIG_SCANNERS_CHOICES,
    SCANNERS_CHOICES,
    SEVERITY_CHOICES,
)


class ImageProvider(Provider):
    """
    Container Image Provider using Trivy for vulnerability and secret scanning.

    This is a Tool/Wrapper provider that delegates all scanning logic to Trivy's
    `trivy image` command and converts the output to Prowler's finding format.
    """

    _type: str = "image"
    FINDING_BATCH_SIZE: int = 100
    MAX_IMAGE_LIST_LINES: int = 10_000
    MAX_IMAGE_NAME_LENGTH: int = 500
    _IMAGE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-_/:@]+$")
    _SHELL_METACHARACTERS = frozenset(";|&$`\n\r")
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        images: list[str] | None = None,
        image_list_file: str | None = None,
        scanners: list[str] | None = None,
        image_config_scanners: list[str] | None = None,
        trivy_severity: list[str] | None = None,
        ignore_unfixed: bool = False,
        timeout: str = "5m",
        config_path: str | None = None,
        config_content: dict | None = None,
        fixer_config: dict | None = None,
    ):
        logger.info("Instantiating Image Provider...")

        self.images = images if images is not None else []
        self.image_list_file = image_list_file
        self.scanners = scanners if scanners is not None else ["vuln", "secret"]
        self.image_config_scanners = (
            image_config_scanners if image_config_scanners is not None else []
        )
        self.trivy_severity = trivy_severity if trivy_severity is not None else []
        self.ignore_unfixed = ignore_unfixed
        self.timeout = timeout
        self.region = "container"
        self.audited_account = "image-scan"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"

        self._validate_inputs()

        # Load images from file if provided
        if image_list_file:
            self._load_images_from_file(image_list_file)

        for image in self.images:
            self._validate_image_name(image)

        if not self.images:
            raise ImageNoImagesProvidedError(
                file=__file__,
                message="No images provided for scanning.",
            )

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config if fixer_config is not None else {}

        # Mutelist (not needed for Image provider since Trivy has its own logic)
        self._mutelist = None

        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=self.audited_account,
            account_name="image",
            region=self.region,
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        Provider.set_global_provider(self)

    def _load_images_from_file(self, file_path: str) -> None:
        """Load image names from a file (one per line)."""
        try:
            line_count = 0
            with open(file_path, "r") as f:
                for line in f:
                    line_count += 1
                    if line_count > self.MAX_IMAGE_LIST_LINES:
                        raise ImageListFileReadError(
                            file=file_path,
                            message=f"Image list file exceeds maximum of {self.MAX_IMAGE_LIST_LINES} lines.",
                        )
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if len(line) > self.MAX_IMAGE_NAME_LENGTH:
                        logger.warning(
                            f"Skipping image name exceeding {self.MAX_IMAGE_NAME_LENGTH} chars at line {line_count} in {file_path}"
                        )
                        continue
                    self.images.append(line)
            logger.info(f"Loaded {len(self.images)} images from {file_path}")
        except FileNotFoundError:
            raise ImageListFileNotFoundError(
                file=file_path,
                message=f"Image list file not found: {file_path}",
            )
        except (ImageListFileReadError, ImageListFileNotFoundError):
            raise
        except Exception as error:
            raise ImageListFileReadError(
                file=file_path,
                original_exception=error,
                message=f"Error reading image list file: {error}",
            )

    def _validate_inputs(self) -> None:
        """Validate timeout, scanners, and severity inputs."""
        if not re.fullmatch(r"\d+[smh]", self.timeout):
            raise ImageInvalidTimeoutError(
                file=__file__,
                message=f"Invalid timeout format: '{self.timeout}'. Expected pattern like '5m', '300s', or '1h'.",
            )

        for scanner in self.scanners:
            if scanner not in SCANNERS_CHOICES:
                raise ImageInvalidScannerError(
                    file=__file__,
                    message=f"Invalid scanner: '{scanner}'. Valid options: {', '.join(SCANNERS_CHOICES)}.",
                )

        for config_scanner in self.image_config_scanners:
            if config_scanner not in IMAGE_CONFIG_SCANNERS_CHOICES:
                raise ImageInvalidConfigScannerError(
                    file=__file__,
                    message=f"Invalid image config scanner: '{config_scanner}'. Valid options: {', '.join(IMAGE_CONFIG_SCANNERS_CHOICES)}.",
                )

        for severity in self.trivy_severity:
            if severity not in SEVERITY_CHOICES:
                raise ImageInvalidSeverityError(
                    file=__file__,
                    message=f"Invalid severity: '{severity}'. Valid options: {', '.join(SEVERITY_CHOICES)}.",
                )

    def _validate_image_name(self, name: str) -> None:
        """Validate a container image name for safety and correctness."""
        if not name:
            raise ImageInvalidNameError(
                file=__file__,
                message="Image name must not be empty.",
            )

        if len(name) > self.MAX_IMAGE_NAME_LENGTH:
            raise ImageInvalidNameError(
                file=__file__,
                message=f"Image name exceeds maximum length of {self.MAX_IMAGE_NAME_LENGTH} characters: '{name[:50]}...'",
            )

        if any(c in self._SHELL_METACHARACTERS for c in name):
            raise ImageInvalidNameError(
                file=__file__,
                message=f"Image name contains invalid characters: '{name}'",
            )

        if not self._IMAGE_NAME_PATTERN.fullmatch(name):
            raise ImageInvalidNameError(
                file=__file__,
                message=f"Image name does not match valid OCI reference format: '{name}'",
            )

    @property
    def auth_method(self) -> str:
        return self._auth_method

    @property
    def type(self) -> str:
        return self._type

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def session(self) -> None:
        return self._session

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    def setup_session(self) -> None:
        """Image provider doesn't need a session since it uses Trivy directly"""
        return None

    def _process_finding(
        self, finding: dict, image_name: str, finding_type: str
    ) -> CheckReportImage:
        """
        Process a single finding and create a CheckReportImage object.

        Args:
            finding: The finding object from Trivy output
            image_name: The container image name being scanned
            finding_type: The type of finding (Vulnerability, Secret, etc.)

        Returns:
            CheckReportImage: The processed check report
        """
        try:
            # Determine finding ID based on type
            if "VulnerabilityID" in finding:
                finding_id = finding["VulnerabilityID"]
                finding_description = finding.get(
                    "Description", finding.get("Title", "")
                )
                finding_status = "FAIL"
            elif "RuleID" in finding:
                # Secret finding
                finding_id = finding["RuleID"]
                finding_description = finding.get("Title", "Secret detected")
                finding_status = "FAIL"
            else:
                finding_id = finding.get("ID", "UNKNOWN")
                finding_description = finding.get("Description", "")
                finding_status = finding.get("Status", "FAIL")

            # Build remediation text for vulnerabilities
            remediation_text = ""
            if finding.get("FixedVersion"):
                remediation_text = f"Upgrade {finding.get('PkgName', 'package')} to version {finding['FixedVersion']}"
            elif finding.get("Resolution"):
                remediation_text = finding["Resolution"]

            # Convert Trivy severity to Prowler severity (lowercase, map UNKNOWN to informational)
            trivy_severity = finding.get("Severity", "UNKNOWN").lower()
            if trivy_severity == "unknown":
                trivy_severity = "informational"

            metadata_dict = {
                "Provider": "image",
                "CheckID": finding_id,
                "CheckTitle": finding.get("Title", finding_id),
                "CheckType": ["Container Image Security"],
                "ServiceName": finding_type,
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": trivy_severity,
                "ResourceType": "container-image",
                "ResourceGroup": "container",
                "Description": finding_description,
                "Risk": finding.get(
                    "Description", "Vulnerability detected in container image"
                ),
                "RelatedUrl": finding.get("PrimaryURL", ""),
                "Remediation": {
                    "Code": {
                        "NativeIaC": "",
                        "Terraform": "",
                        "CLI": "",
                        "Other": "",
                    },
                    "Recommendation": {
                        "Text": remediation_text,
                        "Url": finding.get("PrimaryURL", ""),
                    },
                },
                "Categories": [],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Convert metadata dict to JSON string
            metadata = json.dumps(metadata_dict)

            report = CheckReportImage(
                metadata=metadata, finding=finding, image_name=image_name
            )
            report.status = finding_status
            report.status_extended = self._build_status_extended(finding)
            report.region = self.region
            return report

        except Exception as error:
            raise ImageFindingProcessingError(
                file=__file__,
                original_exception=error,
                message=f"Error processing finding: {error}",
            )

    def _build_status_extended(self, finding: dict) -> str:
        """Build a detailed status message for the finding."""
        parts = []

        if finding.get("VulnerabilityID"):
            parts.append(f"{finding['VulnerabilityID']}")

        if finding.get("PkgName"):
            pkg_info = finding["PkgName"]
            if finding.get("InstalledVersion"):
                pkg_info += f"@{finding['InstalledVersion']}"
            parts.append(f"in package {pkg_info}")

        if finding.get("FixedVersion"):
            parts.append(f"(fix available: {finding['FixedVersion']})")
        elif finding.get("Status") == "will_not_fix":
            parts.append("(no fix available)")

        if finding.get("Title"):
            parts.append(f"- {finding['Title']}")

        return (
            " ".join(parts) if parts else finding.get("Description", "Finding detected")
        )

    def run(self) -> list[CheckReportImage]:
        """Execute the container image scan."""
        reports = []
        for batch in self.run_scan():
            reports.extend(batch)
        return reports

    def run_scan(self) -> Generator[list[CheckReportImage], None, None]:
        """
        Run Trivy scan on all configured images.

        Yields:
            list[CheckReportImage]: Batches of findings
        """
        for image in self.images:
            try:
                yield from self._scan_single_image(image)
            except (ImageScanError, ImageTrivyBinaryNotFoundError):
                raise
            except Exception as error:
                logger.error(f"Error scanning image {image}: {error}")
                continue

    def _scan_single_image(
        self, image: str
    ) -> Generator[list[CheckReportImage], None, None]:
        """
        Scan a single container image with Trivy.

        Args:
            image: The container image name/tag to scan

        Yields:
            list[CheckReportImage]: Batches of findings
        """
        try:
            logger.info(f"Scanning container image: {image}")

            # Build Trivy command
            trivy_command = [
                "trivy",
                "image",
                "--format",
                "json",
                "--scanners",
                ",".join(self.scanners),
                "--timeout",
                self.timeout,
            ]

            if self.image_config_scanners:
                trivy_command.extend(
                    ["--image-config-scanners", ",".join(self.image_config_scanners)]
                )

            if self.trivy_severity:
                trivy_command.extend(["--severity", ",".join(self.trivy_severity)])

            if self.ignore_unfixed:
                trivy_command.append("--ignore-unfixed")

            trivy_command.append(image)

            # Execute Trivy
            process = self._execute_trivy(trivy_command, image)

            # Log stderr output
            if process.stderr:
                self._log_trivy_stderr(process.stderr)

            # Check for Trivy failure
            if process.returncode != 0:
                error_msg = self._extract_trivy_errors(process.stderr)
                categorized_msg = self._categorize_trivy_error(error_msg)
                raise ImageScanError(
                    file=__file__,
                    message=f"Trivy scan failed for {image}: {categorized_msg}",
                )

            # Parse JSON output
            try:
                output = json.loads(process.stdout)
                results = output.get("Results", [])

                if not results:
                    logger.info(f"No findings for image: {image}")
                    return

            except json.JSONDecodeError as error:
                logger.error(f"Failed to parse Trivy output for {image}: {error}")
                logger.debug(f"Trivy stdout: {process.stdout[:500]}")
                return

            # Process findings in batches
            batch = []

            for result in results:
                target = result.get("Target", image)
                result_type = result.get("Type", "unknown")

                # Process Vulnerabilities
                for vuln in result.get("Vulnerabilities", []):
                    report = self._process_finding(vuln, target, result_type)
                    batch.append(report)
                    if len(batch) >= self.FINDING_BATCH_SIZE:
                        yield batch
                        batch = []

                # Process Secrets
                for secret in result.get("Secrets", []):
                    report = self._process_finding(secret, target, "secret")
                    batch.append(report)
                    if len(batch) >= self.FINDING_BATCH_SIZE:
                        yield batch
                        batch = []

                # Process Misconfigurations (from Dockerfile)
                for misconfig in result.get("Misconfigurations", []):
                    report = self._process_finding(
                        misconfig, target, "misconfiguration"
                    )
                    batch.append(report)
                    if len(batch) >= self.FINDING_BATCH_SIZE:
                        yield batch
                        batch = []

            # Yield remaining findings
            if batch:
                yield batch

        except (ImageScanError, ImageTrivyBinaryNotFoundError):
            raise
        except Exception as error:
            if "No such file or directory: 'trivy'" in str(error):
                raise ImageTrivyBinaryNotFoundError(
                    file=__file__,
                    original_exception=error,
                    message="Trivy binary not found. Please install Trivy from https://trivy.dev/latest/getting-started/installation/",
                )
            logger.error(f"Error scanning image {image}: {error}")

    def _execute_trivy(self, command: list, image: str) -> subprocess.CompletedProcess:
        """Execute Trivy command with optional progress bar."""
        try:
            if sys.stdout.isatty():
                with alive_bar(
                    ctrl_c=False,
                    bar="blocks",
                    spinner="classic",
                    stats=False,
                    enrich_print=False,
                ) as bar:
                    bar.title = f"-> Scanning {image}..."
                    process = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                    )
                    bar.title = f"-> Scan completed for {image}"
                    return process
            else:
                logger.info(f"Scanning {image}...")
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                )
                logger.info(f"Scan completed for {image}")
                return process
        except (AttributeError, OSError):
            logger.info(f"Scanning {image}...")
            return subprocess.run(command, capture_output=True, text=True)

    def _log_trivy_stderr(self, stderr: str) -> None:
        """Parse and log Trivy's stderr output."""
        for line in stderr.strip().split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    level = parts[1]
                    message = " ".join(parts[2:])
                    if level == "ERROR":
                        logger.error(message)
                    elif level == "WARN":
                        logger.warning(message)
                    elif level == "INFO":
                        logger.info(message)
                    elif level == "DEBUG":
                        logger.debug(message)
                    else:
                        logger.info(message)
                else:
                    logger.info(line)

    @staticmethod
    def _extract_trivy_errors(stderr: str) -> str:
        """Extract only ERROR-level messages from Trivy stderr output."""
        if not stderr:
            return "Unknown error"
        error_lines = []
        for line in stderr.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "ERROR":
                error_lines.append(" ".join(parts[2:]))
            elif len(parts) >= 3 and parts[1] == "FATAL":
                error_lines.append(" ".join(parts[2:]))
        if error_lines:
            return "; ".join(error_lines)[:500]
        # Fallback: no ERROR lines found, return last non-empty line
        for line in reversed(stderr.strip().split("\n")):
            if line.strip():
                return line.strip()[:500]
        return "Unknown error"

    @staticmethod
    def _categorize_trivy_error(error_msg: str) -> str:
        """Categorize a Trivy error message to provide actionable guidance."""
        lower = error_msg.lower()

        if any(kw in lower for kw in ("401", "403", "unauthorized", "denied")):
            return f"Auth failure — check `docker login`: {error_msg}"
        if any(kw in lower for kw in ("404", "manifest unknown", "not found")):
            return f"Image not found — check name/tag/registry: {error_msg}"
        if any(kw in lower for kw in ("429", "rate limit", "too many requests")):
            return f"Rate limited — wait or authenticate: {error_msg}"
        if any(kw in lower for kw in ("timeout", "connection refused", "no such host")):
            return f"Network issue — check connectivity: {error_msg}"

        return error_msg

    def print_credentials(self) -> None:
        """Print scan configuration."""
        report_title = f"{Style.BRIGHT}Scanning container images:{Style.RESET_ALL}"

        report_lines = []
        if len(self.images) <= 3:
            for img in self.images:
                report_lines.append(f"Image: {Fore.YELLOW}{img}{Style.RESET_ALL}")
        else:
            report_lines.append(
                f"Images: {Fore.YELLOW}{len(self.images)} images{Style.RESET_ALL}"
            )

        report_lines.append(
            f"Scanners: {Fore.YELLOW}{', '.join(self.scanners)}{Style.RESET_ALL}"
        )

        if self.image_config_scanners:
            report_lines.append(
                f"Image config scanners: {Fore.YELLOW}{', '.join(self.image_config_scanners)}{Style.RESET_ALL}"
            )

        if self.trivy_severity:
            report_lines.append(
                f"Severity filter: {Fore.YELLOW}{', '.join(self.trivy_severity)}{Style.RESET_ALL}"
            )

        if self.ignore_unfixed:
            report_lines.append(f"Ignore unfixed: {Fore.YELLOW}Yes{Style.RESET_ALL}")

        report_lines.append(f"Timeout: {Fore.YELLOW}{self.timeout}{Style.RESET_ALL}")

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        image: str | None = None,
        raise_on_exception: bool = True,
        provider_id: str | None = None,
    ) -> "Connection":
        """
        Test connection to container registry by attempting to inspect an image.

        Args:
            image: Container image to test
            raise_on_exception: Whether to raise exceptions
            provider_id: Fallback for image name

        Returns:
            Connection: Connection object with success status
        """
        try:
            if provider_id and not image:
                image = provider_id

            if not image:
                return Connection(is_connected=False, error="Image name is required")

            # Test by running trivy with --skip-update to just test image access
            process = subprocess.run(
                [
                    "trivy",
                    "image",
                    "--skip-db-update",
                    "--download-db-only=false",
                    image,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if process.returncode == 0:
                return Connection(is_connected=True)
            else:
                error_msg = process.stderr or "Unknown error"
                if "401" in error_msg or "unauthorized" in error_msg.lower():
                    return Connection(
                        is_connected=False,
                        error="Authentication failed. Check registry credentials.",
                    )
                elif "not found" in error_msg.lower() or "404" in error_msg:
                    return Connection(
                        is_connected=False,
                        error="Image not found in registry.",
                    )
                else:
                    return Connection(
                        is_connected=False,
                        error=f"Failed to access image: {error_msg[:200]}",
                    )

        except subprocess.TimeoutExpired:
            return Connection(
                is_connected=False,
                error="Connection timed out",
            )
        except FileNotFoundError:
            return Connection(
                is_connected=False,
                error="Trivy binary not found. Please install Trivy.",
            )
        except Exception as error:
            if raise_on_exception:
                raise
            return Connection(
                is_connected=False,
                error=f"Unexpected error: {str(error)}",
            )
