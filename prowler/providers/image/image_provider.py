from __future__ import annotations

import json
import os
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
    ImageInvalidFilterError,
    ImageInvalidNameError,
    ImageInvalidScannerError,
    ImageInvalidSeverityError,
    ImageInvalidTimeoutError,
    ImageListFileNotFoundError,
    ImageListFileReadError,
    ImageMaxImagesExceededError,
    ImageNoImagesProvidedError,
    ImageRegistryAuthError,
    ImageRegistryCatalogError,
    ImageRegistryNetworkError,
    ImageScanError,
    ImageTrivyBinaryNotFoundError,
)
from prowler.providers.image.lib.arguments.arguments import (
    IMAGE_CONFIG_SCANNERS_CHOICES,
    SCANNERS_CHOICES,
    SEVERITY_CHOICES,
)
from prowler.providers.image.lib.registry.dockerhub_adapter import DockerHubAdapter
from prowler.providers.image.lib.registry.factory import create_registry_adapter


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
        registry_username: str | None = None,
        registry_password: str | None = None,
        registry_token: str | None = None,
        registry: str | None = None,
        image_filter: str | None = None,
        tag_filter: str | None = None,
        max_images: int = 0,
        registry_insecure: bool = False,
        registry_list_images: bool = False,
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
        self._listing_only = False

        # Registry authentication (follows IaC pattern: explicit params, env vars internal)
        self.registry_username = registry_username or os.environ.get(
            "REGISTRY_USERNAME"
        )
        self.registry_password = registry_password or os.environ.get(
            "REGISTRY_PASSWORD"
        )
        self.registry_token = registry_token or os.environ.get("REGISTRY_TOKEN")

        if self.registry_username and self.registry_password:
            self._auth_method = "Docker login"
            logger.info("Using docker login for registry authentication")
        elif self.registry_token:
            self._auth_method = "Registry token"
            logger.info("Using registry token for authentication")
        else:
            self._auth_method = "No auth"

        # Registry scan mode
        self.registry = registry
        self.image_filter = image_filter
        self.tag_filter = tag_filter
        self.max_images = max_images
        self.registry_insecure = registry_insecure
        self.registry_list_images = registry_list_images

        # Compile regex filters
        self._image_filter_re = None
        self._tag_filter_re = None
        if self.image_filter:
            try:
                self._image_filter_re = re.compile(self.image_filter)
            except re.error as exc:
                raise ImageInvalidFilterError(
                    file=__file__,
                    message=f"Invalid --image-filter regex '{self.image_filter}': {exc}",
                )
        if self.tag_filter:
            try:
                self._tag_filter_re = re.compile(self.tag_filter)
            except re.error as exc:
                raise ImageInvalidFilterError(
                    file=__file__,
                    message=f"Invalid --tag-filter regex '{self.tag_filter}': {exc}",
                )

        self._validate_inputs()

        # Load images from file if provided
        if image_list_file:
            self._load_images_from_file(image_list_file)

        # Registry scan mode: enumerate images from registry
        if self.registry:
            self._enumerate_registry()
            if self._listing_only:
                return

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

    @staticmethod
    def _extract_registry(image: str) -> str | None:
        """Extract registry hostname from an image reference.

        Returns None for Docker Hub images (no registry prefix).
        """
        parts = image.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0]):
            return parts[0]
        return None

    @staticmethod
    def _is_registry_url(image_uid: str) -> bool:
        """Determine whether an image UID is a registry URL (namespace only).

        A registry URL like ``docker.io/andoniaf`` has a registry host but
        the remaining part contains no ``/`` (no repo) and no ``:`` (no tag).
        """
        registry_host = ImageProvider._extract_registry(image_uid)
        if not registry_host:
            return False
        repo_and_tag = image_uid[len(registry_host) + 1 :]
        return "/" not in repo_and_tag and ":" not in repo_and_tag

    def cleanup(self) -> None:
        """Clean up any resources after scanning."""

    def _process_finding(
        self,
        finding: dict,
        image: str,
        trivy_target: str,
        image_sha: str = "",
    ) -> CheckReportImage:
        """
        Process a single finding and create a CheckReportImage object.

        Args:
            finding: The finding object from Trivy output
            image: The clean container image name (e.g., "alpine:3.18")
            trivy_target: The Trivy target string (e.g., "alpine:3.18 (alpine 3.18.0)")
            image_sha: Short SHA from Trivy Metadata.ImageID for resource uniqueness

        Returns:
            CheckReportImage: The processed check report
        """
        try:
            # Determine finding ID and category based on type
            if "VulnerabilityID" in finding:
                finding_id = finding["VulnerabilityID"]
                finding_description = finding.get(
                    "Description", finding.get("Title", "")
                )
                finding_status = "FAIL"
                finding_categories = ["vulnerability"]
            elif "RuleID" in finding:
                # Secret finding
                finding_id = finding["RuleID"]
                finding_description = finding.get("Title", "Secret detected")
                finding_status = "FAIL"
                finding_categories = ["secrets"]
            else:
                finding_id = finding.get("ID", "UNKNOWN")
                finding_description = finding.get("Description", "")
                finding_status = finding.get("Status", "FAIL")
                finding_categories = []

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
                "ServiceName": "container-image",
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": trivy_severity,
                "ResourceType": "container-image",
                "ResourceGroup": "container",
                "Description": finding_description,
                "Risk": finding.get(
                    "Description", "Vulnerability detected in container image"
                ),
                "RelatedUrl": "",
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
                "Categories": finding_categories,
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Convert metadata dict to JSON string
            metadata = json.dumps(metadata_dict)

            report = CheckReportImage(
                metadata=metadata, finding=finding, image_name=image
            )
            report.status = finding_status
            report.status_extended = self._build_status_extended(finding)
            report.region = self.region
            report.image_sha = image_sha
            report.resource_details = trivy_target
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
        try:
            reports = []
            for batch in self.run_scan():
                reports.extend(batch)
            return reports
        finally:
            self.cleanup()

    def scan_per_image(
        self,
    ) -> Generator[tuple[str, list[CheckReportImage]], None, None]:
        """Scan images one by one, yielding (image_name, findings) per image.

        Unlike run() which returns all findings at once, this method yields
        after each image completes, enabling progress tracking.
        """
        try:
            for image in self.images:
                try:
                    image_findings = []
                    for batch in self._scan_single_image(image):
                        image_findings.extend(batch)
                    yield (image, image_findings)
                except (ImageScanError, ImageTrivyBinaryNotFoundError):
                    raise
                except Exception as error:
                    logger.error(f"Error scanning image {image}: {error}")
                    yield (image, [])
        finally:
            self.cleanup()

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

                # Extract image digest for resource uniqueness
                trivy_metadata = output.get("Metadata", {})
                image_id = trivy_metadata.get("ImageID", "")
                if not image_id:
                    repo_digests = trivy_metadata.get("RepoDigests", [])
                    if repo_digests:
                        image_id = (
                            repo_digests[0].split("@")[-1]
                            if "@" in repo_digests[0]
                            else ""
                        )
                short_sha = image_id.replace("sha256:", "")[:12] if image_id else ""

            except json.JSONDecodeError as error:
                logger.error(f"Failed to parse Trivy output for {image}: {error}")
                logger.debug(f"Trivy stdout: {process.stdout[:500]}")
                return

            # Process findings in batches
            batch = []

            for result in results:
                target = result.get("Target", image)

                # Process Vulnerabilities
                for vuln in result.get("Vulnerabilities", []):
                    report = self._process_finding(
                        vuln, image, target, image_sha=short_sha
                    )
                    batch.append(report)
                    if len(batch) >= self.FINDING_BATCH_SIZE:
                        yield batch
                        batch = []

                # Process Secrets
                for secret in result.get("Secrets", []):
                    report = self._process_finding(
                        secret, image, target, image_sha=short_sha
                    )
                    batch.append(report)
                    if len(batch) >= self.FINDING_BATCH_SIZE:
                        yield batch
                        batch = []

                # Process Misconfigurations (from Dockerfile)
                for misconfig in result.get("Misconfigurations", []):
                    report = self._process_finding(
                        misconfig, image, target, image_sha=short_sha
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

    def _build_trivy_env(self) -> dict:
        """Build environment variables for Trivy, injecting registry credentials."""
        env = dict(os.environ)
        if self.registry_username and self.registry_password:
            env["TRIVY_USERNAME"] = self.registry_username
            env["TRIVY_PASSWORD"] = self.registry_password
        elif self.registry_token:
            env["TRIVY_REGISTRY_TOKEN"] = self.registry_token
        return env

    def _execute_trivy(self, command: list, image: str) -> subprocess.CompletedProcess:
        """Execute Trivy command with optional progress bar."""
        env = self._build_trivy_env()
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
                        env=env,
                    )
                    bar.title = f"-> Scan completed for {image}"
                    return process
            else:
                logger.info(f"Scanning {image}...")
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                logger.info(f"Scan completed for {image}")
                return process
        except (AttributeError, OSError):
            logger.info(f"Scanning {image}...")
            return subprocess.run(command, capture_output=True, text=True, env=env)

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

    def _enumerate_registry(self) -> None:
        """Enumerate images from a registry using the appropriate adapter."""
        verify_ssl = not self.registry_insecure
        adapter = create_registry_adapter(
            registry_url=self.registry,
            username=self.registry_username,
            password=self.registry_password,
            token=self.registry_token,
            verify_ssl=verify_ssl,
        )

        repositories = adapter.list_repositories()
        logger.info(
            f"Discovered {len(repositories)} repositories from registry {self.registry}"
        )

        # Apply image filter
        if self._image_filter_re:
            repositories = [r for r in repositories if self._image_filter_re.search(r)]
            logger.info(
                f"{len(repositories)} repositories match --image-filter '{self.image_filter}'"
            )

        if not repositories:
            logger.warning(
                f"No repositories found in registry {self.registry} (after filtering)"
            )
            return

        # Determine if this is a Docker Hub adapter (for image reference format)
        is_dockerhub = isinstance(adapter, DockerHubAdapter)

        discovered_images = []
        repos_tags: dict[str, list[str]] = {}
        for repo in repositories:
            tags = adapter.list_tags(repo)

            # Apply tag filter
            if self._tag_filter_re:
                tags = [t for t in tags if self._tag_filter_re.search(t)]

            if tags:
                repos_tags[repo] = tags

            for tag in tags:
                if is_dockerhub:
                    # Docker Hub images don't need a host prefix
                    image_ref = f"{repo}:{tag}"
                else:
                    # OCI registries need the full host/repo:tag reference
                    registry_host = self.registry.rstrip("/")
                    for prefix in ("https://", "http://"):
                        if registry_host.startswith(prefix):
                            registry_host = registry_host[len(prefix) :]
                            break
                    image_ref = f"{registry_host}/{repo}:{tag}"
                discovered_images.append(image_ref)

        # Registry list mode: print listing and return early
        if self.registry_list_images:
            self._print_registry_listing(repos_tags, len(discovered_images))
            self._listing_only = True
            return

        # Check max-images limit
        if self.max_images and len(discovered_images) > self.max_images:
            raise ImageMaxImagesExceededError(
                file=__file__,
                message=f"Discovered {len(discovered_images)} images, exceeding --max-images {self.max_images}. Use --image-filter or --tag-filter to narrow results.",
            )

        # Deduplicate with explicit images
        existing = set(self.images)
        for img in discovered_images:
            if img not in existing:
                self.images.append(img)
                existing.add(img)

        logger.info(
            f"Discovered {len(discovered_images)} images from registry {self.registry} "
            f"({len(repositories)} repositories). Total images to scan: {len(self.images)}"
        )

    def _print_registry_listing(
        self, repos_tags: dict[str, list[str]], total_images: int
    ) -> None:
        """Print a structured listing of registry repositories and tags."""
        num_repos = len(repos_tags)
        print(
            f"\n{Style.BRIGHT}Registry:{Style.RESET_ALL} "
            f"{Fore.CYAN}{self.registry}{Style.RESET_ALL} "
            f"({num_repos} {'repository' if num_repos == 1 else 'repositories'}, "
            f"{total_images} {'image' if total_images == 1 else 'images'})\n"
        )
        for repo, tags in repos_tags.items():
            print(f"  {Fore.YELLOW}{repo}{Style.RESET_ALL} " f"({len(tags)} tags)")
            print(f"    {', '.join(tags)}")
        print()

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

        report_lines.append(
            f"Authentication method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}"
        )

        if self.registry:
            report_lines.append(
                f"Registry: {Fore.YELLOW}{self.registry}{Style.RESET_ALL}"
            )
            if self.image_filter:
                report_lines.append(
                    f"Image filter: {Fore.YELLOW}{self.image_filter}{Style.RESET_ALL}"
                )
            if self.tag_filter:
                report_lines.append(
                    f"Tag filter: {Fore.YELLOW}{self.tag_filter}{Style.RESET_ALL}"
                )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        image: str | None = None,
        raise_on_exception: bool = True,
        provider_id: str | None = None,
        registry_username: str | None = None,
        registry_password: str | None = None,
        registry_token: str | None = None,
    ) -> "Connection":
        """
        Test connection to container registry by verifying image accessibility.

        Handles two cases:
        - Image reference (e.g. ``alpine:3.18``, ``ghcr.io/user/repo:tag``):
          verifies the specific tag exists.
        - Registry URL (e.g. ``docker.io/namespace``, ``ghcr.io/org``):
          verifies we can list repositories in that namespace.

        Uses registry HTTP APIs directly instead of Trivy to avoid false
        failures caused by Trivy DB download issues.

        Args:
            image: Container image or registry URL to test
            raise_on_exception: Whether to raise exceptions
            provider_id: Fallback for image name
            registry_username: Registry username for basic auth
            registry_password: Registry password for basic auth
            registry_token: Registry token for token-based auth

        Returns:
            Connection: Connection object with success status
        """
        try:
            if provider_id and not image:
                image = provider_id

            if not image:
                return Connection(is_connected=False, error="Image name is required")

            if ImageProvider._is_registry_url(image):
                # Registry enumeration mode — test by listing repositories
                adapter = create_registry_adapter(
                    registry_url=image,
                    username=registry_username,
                    password=registry_password,
                    token=registry_token,
                )
                adapter.list_repositories()
                return Connection(is_connected=True)

            # Image reference mode — verify the specific tag exists
            registry_host = ImageProvider._extract_registry(image)
            repo_and_tag = image[len(registry_host) + 1 :] if registry_host else image
            if ":" in repo_and_tag:
                repository, tag = repo_and_tag.rsplit(":", 1)
            else:
                repository = repo_and_tag
                tag = "latest"

            is_dockerhub = not registry_host or registry_host in (
                "docker.io",
                "registry-1.docker.io",
            )

            # Docker Hub official images use "library/" prefix
            if is_dockerhub and "/" not in repository:
                repository = f"library/{repository}"

            if is_dockerhub:
                registry_url = f"docker.io/{repository.split('/')[0]}"
            else:
                registry_url = registry_host

            adapter = create_registry_adapter(
                registry_url=registry_url,
                username=registry_username,
                password=registry_password,
                token=registry_token,
            )

            tags = adapter.list_tags(repository)
            if tag not in tags:
                return Connection(
                    is_connected=False,
                    error=f"Tag '{tag}' not found for image '{image}'.",
                )

            return Connection(is_connected=True)

        except ImageRegistryAuthError:
            return Connection(
                is_connected=False,
                error="Authentication failed. Check registry credentials.",
            )
        except (ImageRegistryNetworkError, ImageRegistryCatalogError) as exc:
            return Connection(
                is_connected=False,
                error=f"Failed to access image: {str(exc)[:200]}",
            )
        except Exception as error:
            if raise_on_exception:
                raise
            return Connection(
                is_connected=False,
                error=f"Unexpected error: {str(error)}",
            )
