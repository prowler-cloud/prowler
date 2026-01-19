import json
import re
import shutil
import subprocess
import sys
import tempfile
from os import environ
from typing import Generator, List

from alive_progress import alive_bar
from colorama import Fore, Style
from dulwich import porcelain

from prowler.config.config import (
    default_config_file_path,
    load_and_validate_config_file,
)
from prowler.lib.check.models import CheckReportIAC
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class IacProvider(Provider):
    _type: str = "iac"
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        scan_path: str = ".",
        scan_repository_url: str = None,
        scanners: list[str] = ["vuln", "misconfig", "secret"],
        exclude_path: list[str] = [],
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        github_username: str = None,
        personal_access_token: str = None,
        oauth_app_token: str = None,
    ):
        logger.info("Instantiating IAC Provider...")

        self.scan_path = scan_path
        self.scan_repository_url = scan_repository_url
        self.scanners = scanners
        self.exclude_path = exclude_path
        self.region = "branch"
        self.audited_account = "local-iac"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"
        self._temp_clone_dir = None  # Track temporary directory for cleanup

        if scan_repository_url:
            oauth_app_token = oauth_app_token or environ.get("GITHUB_OAUTH_APP_TOKEN")
            github_username = github_username or environ.get("GITHUB_USERNAME")
            personal_access_token = personal_access_token or environ.get(
                "GITHUB_PERSONAL_ACCESS_TOKEN"
            )

            if oauth_app_token:
                self.oauth_app_token = oauth_app_token
                self.github_username = None
                self.personal_access_token = None
                self._auth_method = "OAuth App Token"
                logger.info("Using OAuth App Token for GitHub authentication")
            elif github_username and personal_access_token:
                self.github_username = github_username
                self.personal_access_token = personal_access_token
                self.oauth_app_token = None
                self._auth_method = "Personal Access Token"
                logger.info(
                    "Using GitHub username and personal access token for authentication"
                )
            else:
                self.github_username = None
                self.personal_access_token = None
                self.oauth_app_token = None
                logger.debug(
                    "No GitHub authentication method provided; proceeding without authentication."
                )

            # Clone repository and detect branch during initialization
            # This ensures the branch is detected for both CLI and API usage
            self._temp_clone_dir, branch_name = self._clone_repository(
                self.scan_repository_url,
                self.github_username,
                self.personal_access_token,
                self.oauth_app_token,
            )
            # Update scan_path to point to the cloned repository
            self.scan_path = self._temp_clone_dir
            # Update region with the detected branch name
            self.region = branch_name
            logger.info(f"Updated region to branch: {branch_name}")

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist (not needed for IAC since Trivy has its own mutelist logic)
        self._mutelist = None

        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=self.audited_account,
            account_name="iac",
            region=self.region,
            services_scanned=0,  # IAC doesn't use services
            expected_checks=[],  # IAC doesn't use checks
            completed_checks=0,  # IAC doesn't use checks
            audit_progress=0,  # IAC doesn't use progress tracking
        )

        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        return self._auth_method

    @property
    def type(self):
        return self._type

    @property
    def identity(self):
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    def __del__(self):
        """Cleanup temporary directory when provider is destroyed"""
        self.cleanup()

    def cleanup(self):
        """Remove temporary cloned repository if it exists"""
        if self._temp_clone_dir:
            try:
                logger.info(f"Removing temporary directory {self._temp_clone_dir}...")
                shutil.rmtree(self._temp_clone_dir)
                self._temp_clone_dir = None
            except Exception as error:
                logger.warning(f"Failed to remove temporary directory: {error}")

    def setup_session(self):
        """IAC provider doesn't need a session since it uses Trivy directly"""
        return None

    def _process_finding(
        self, finding: dict, file_path: str, type: str
    ) -> CheckReportIAC:
        """
        Process a single check (failed or passed) and create a CheckReportIAC object.

        Args:
            finding: The finding object from Trivy output
            file_path: The path to the file that contains the finding
            type: The type of the finding

        Returns:
            CheckReportIAC: The processed check report
        """
        try:
            if "VulnerabilityID" in finding:
                finding_id = finding["VulnerabilityID"]
                finding_description = finding["Description"]
                finding_status = finding.get("Status", "FAIL")
            elif "RuleID" in finding:
                finding_id = finding["RuleID"]
                finding_description = finding["Title"]
                finding_status = finding.get("Status", "FAIL")
            else:
                finding_id = finding["ID"]
                finding_description = finding["Description"]
                finding_status = finding["Status"]

            metadata_dict = {
                "Provider": "iac",
                "CheckID": finding_id,
                "CheckTitle": finding["Title"],
                "CheckType": ["Infrastructure as Code"],
                "ServiceName": type,
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": finding["Severity"],
                "ResourceType": "iac",
                "Description": finding_description,
                "Risk": "This provider has not defined a risk for this check.",
                "RelatedUrl": finding.get("PrimaryURL", ""),
                "Remediation": {
                    "Code": {
                        "NativeIaC": "",
                        "Terraform": "",
                        "CLI": "",
                        "Other": "",
                    },
                    "Recommendation": {
                        "Text": finding.get("Resolution", ""),
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

            report = CheckReportIAC(
                metadata=metadata, finding=finding, file_path=file_path
            )
            report.status = finding_status
            report.status_extended = (
                finding.get("Message", "")
                if finding.get("Message")
                else finding.get("Description", "")
            )
            if finding_status == "MUTED":
                report.muted = True
            # Set the region from the provider
            report.region = self.region
            return report
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _detect_branch_name(self, repo_path: str) -> str:
        """
        Detect the current branch name from a cloned repository.

        Args:
            repo_path: Path to the cloned repository

        Returns:
            str: The branch name, defaulting to "main" if detection fails
        """
        try:
            import os

            # Read .git/HEAD to detect the current branch
            head_file = os.path.join(repo_path, ".git", "HEAD")
            if os.path.exists(head_file):
                with open(head_file, "r") as f:
                    content = f.read().strip()
                    # Format: "ref: refs/heads/branch-name"
                    if content.startswith("ref: refs/heads/"):
                        branch_name = content[16:]  # Remove "ref: refs/heads/"
                        logger.info(f"Detected branch: {branch_name}")
                        return branch_name

            # Fallback: return "main" as default
            logger.warning("Could not detect branch name, defaulting to 'main'")
            return "main"

        except Exception as error:
            logger.error(f"Error detecting branch name: {error}")
            return "main"  # Safe fallback

    def _clone_repository(
        self,
        repository_url: str,
        github_username: str = None,
        personal_access_token: str = None,
        oauth_app_token: str = None,
    ) -> tuple[str, str]:
        """
        Clone a git repository to a temporary directory, supporting GitHub authentication.

        Returns:
            tuple[str, str]: (temporary_directory, branch_name)
        """
        try:
            original_url = repository_url

            if github_username and personal_access_token:
                repository_url = repository_url.replace(
                    "https://github.com/",
                    f"https://{github_username}:{personal_access_token}@github.com/",
                )
            elif oauth_app_token:
                repository_url = repository_url.replace(
                    "https://github.com/",
                    f"https://oauth2:{oauth_app_token}@github.com/",
                )

            temporary_directory = tempfile.mkdtemp()
            logger.info(
                f"Cloning repository {original_url} into {temporary_directory}..."
            )

            # Check if we're in an environment with a TTY
            # Celery workers and other non-interactive environments don't have TTY
            #   and cannot use the alive_bar
            try:
                if sys.stdout.isatty():
                    with alive_bar(
                        ctrl_c=False,
                        bar="blocks",
                        spinner="classic",
                        stats=False,
                        enrich_print=False,
                    ) as bar:
                        try:
                            bar.title = f"-> Cloning {original_url}..."
                            porcelain.clone(
                                repository_url, temporary_directory, depth=1
                            )
                            bar.title = "-> Repository cloned successfully!"
                        except Exception as clone_error:
                            bar.title = "-> Cloning failed!"
                            raise clone_error
                else:
                    # No TTY, just clone without progress bar
                    logger.info(f"Cloning {original_url}...")
                    porcelain.clone(repository_url, temporary_directory, depth=1)
                    logger.info("Repository cloned successfully!")
            except (AttributeError, OSError):
                # Fallback if isatty() check fails
                logger.info(f"Cloning {original_url}...")
                porcelain.clone(repository_url, temporary_directory, depth=1)
                logger.info("Repository cloned successfully!")

            # Detect the branch name from the cloned repository
            branch_name = self._detect_branch_name(temporary_directory)

            return temporary_directory, branch_name
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def run(self) -> List[CheckReportIAC]:
        """
        Execute the IaC scan.

        Note: Repository cloning and branch detection now happen in __init__(),
        so this method just runs the scan and returns results.
        For CLI compatibility, cleanup is still performed at the end.
        """
        try:
            # Collect all batches from the generator
            # scan_path now points to either the local directory or the cloned repo
            reports = []
            for batch in self.run_scan(
                self.scan_path, self.scanners, self.exclude_path
            ):
                reports.extend(batch)
        finally:
            # Clean up temporary directory if this was a repository scan
            # This ensures CLI usage cleans up immediately after run()
            if self._temp_clone_dir:
                self.cleanup()

        return reports

    def run_scan(
        self, directory: str, scanners: list[str], exclude_path: list[str]
    ) -> Generator[List[CheckReportIAC], None, None]:
        try:
            logger.info(f"Running IaC scan on {directory} ...")
            trivy_command = [
                "trivy",
                "fs",
                directory,
                "--format",
                "json",
                "--scanners",
                ",".join(scanners),
                "--parallel",
                "0",
                "--include-non-failures",
            ]
            if exclude_path:
                trivy_command.extend(["--skip-dirs", ",".join(exclude_path)])

            # Check if we're in an environment with a TTY
            try:
                if sys.stdout.isatty():
                    with alive_bar(
                        ctrl_c=False,
                        bar="blocks",
                        spinner="classic",
                        stats=False,
                        enrich_print=False,
                    ) as bar:
                        try:
                            bar.title = f"-> Running IaC scan on {directory} ..."
                            # Run Trivy with JSON output
                            process = subprocess.run(
                                trivy_command,
                                capture_output=True,
                                text=True,
                            )
                            bar.title = "-> Scan completed!"
                        except Exception as error:
                            bar.title = "-> Scan failed!"
                            raise error
                else:
                    # No TTY, just run without progress bar
                    logger.info(f"Running Trivy scan on {directory}...")
                    process = subprocess.run(
                        trivy_command,
                        capture_output=True,
                        text=True,
                    )
                    logger.info("Trivy scan completed!")
            except (AttributeError, OSError):
                # Fallback if isatty() check fails
                logger.info(f"Running Trivy scan on {directory}...")
                process = subprocess.run(
                    trivy_command,
                    capture_output=True,
                    text=True,
                )
                logger.info("Trivy scan completed!")
            # Log Trivy's stderr output with preserved log levels
            if process.stderr:
                for line in process.stderr.strip().split("\n"):
                    if line.strip():
                        # Parse Trivy's log format to extract level and message
                        # Trivy format: timestamp level message
                        parts = line.split()
                        if len(parts) >= 3:
                            # Extract level and message
                            level = parts[1]
                            message = " ".join(parts[2:])

                            # Map Trivy log levels to Python logging levels
                            if level == "ERROR":
                                logger.error(f"{message}")
                            elif level == "WARN":
                                logger.warning(f"{message}")
                            elif level == "INFO":
                                logger.info(f"{message}")
                            elif level == "DEBUG":
                                logger.debug(f"{message}")
                            else:
                                # Default to info for unknown levels
                                logger.info(f"{message}")
                        else:
                            # If we can't parse the format, log as info
                            logger.info(f"{line}")

            try:
                output = json.loads(process.stdout).get("Results", [])

                if not output:
                    logger.warning("No findings returned from Trivy scan")
                    return
            except Exception as error:
                logger.critical(
                    f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                )
                sys.exit(1)

            batch = []
            batch_size = 100

            # Process all trivy findings
            for finding in output:

                # Process Misconfigurations
                for misconfiguration in finding.get("Misconfigurations", []):
                    report = self._process_finding(
                        misconfiguration, finding["Target"], finding["Type"]
                    )
                    batch.append(report)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

                # Process Vulnerabilities
                for vulnerability in finding.get("Vulnerabilities", []):
                    report = self._process_finding(
                        vulnerability, finding["Target"], finding["Type"]
                    )
                    batch.append(report)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

                # Process Secrets
                for secret in finding.get("Secrets", []):
                    report = self._process_finding(
                        secret, finding["Target"], finding["Class"]
                    )
                    batch.append(report)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

                # Process Licenses
                for license in finding.get("Licenses", []):
                    report = self._process_finding(
                        license, finding["Target"], finding["Type"]
                    )
                    batch.append(report)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

            # Yield any remaining findings in the last batch
            if batch:
                yield batch

        except Exception as error:
            if "No such file or directory: 'trivy'" in str(error):
                logger.critical(
                    "Trivy binary not found. Please install Trivy from https://trivy.dev/latest/getting-started/installation/ or use your system package manager (e.g., 'brew install trivy' on macOS, 'apt-get install trivy' on Ubuntu)"
                )
                sys.exit(1)
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def print_credentials(self):
        if self.scan_repository_url:
            report_title = (
                f"{Style.BRIGHT}Scanning remote IaC repository:{Style.RESET_ALL}"
            )
            report_lines = [
                f"Repository: {Fore.YELLOW}{self.scan_repository_url}{Style.RESET_ALL}",
            ]
        else:
            report_title = (
                f"{Style.BRIGHT}Scanning local IaC directory:{Style.RESET_ALL}"
            )
            report_lines = [
                f"Directory: {Fore.YELLOW}{self.scan_path}{Style.RESET_ALL}",
            ]

        if self.exclude_path:
            report_lines.append(
                f"Excluded paths: {Fore.YELLOW}{', '.join(self.exclude_path)}{Style.RESET_ALL}"
            )

        report_lines.append(
            f"Scanners: {Fore.YELLOW}{', '.join(self.scanners)}{Style.RESET_ALL}"
        )

        report_lines.append(
            f"Authentication method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}"
        )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        scan_repository_url: str = None,
        oauth_app_token: str = None,
        access_token: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> "Connection":
        """Test connection to IaC repository.

        Test the connection to the IaC repository using the provided credentials.

        Args:
            scan_repository_url (str): Repository URL to scan.
            oauth_app_token (str): OAuth App token for authentication.
            access_token (str): Access token for authentication (alias for oauth_app_token).
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.
            provider_id (str): The provider ID, in this case it's the repository URL.

        Returns:
            Connection: Connection object with success status or error information.

        Raises:
            Exception: If failed to test the connection to the repository.

        Examples:
            >>> IacProvider.test_connection(scan_repository_url="https://github.com/user/repo")
            Connection(is_connected=True)
        """
        try:
            # If provider_id is provided and scan_repository_url is not, use provider_id as the repository URL
            if provider_id and not scan_repository_url:
                scan_repository_url = provider_id

            # Handle both oauth_app_token and access_token parameters
            if access_token and not oauth_app_token:
                oauth_app_token = access_token

            if not scan_repository_url:
                return Connection(
                    is_connected=False, error="Repository URL is required"
                )

            # Try to clone the repository to test the connection
            with tempfile.TemporaryDirectory():
                try:
                    if oauth_app_token:
                        # If token is provided, use it for authentication
                        # Extract the domain and path from the URL
                        url_pattern = r"(https?://)([^/]+)/(.+)"
                        match = re.match(url_pattern, scan_repository_url)
                        if match:
                            protocol, domain, path = match.groups()
                            # Construct URL with token
                            auth_url = f"{protocol}x-access-token:{oauth_app_token}@{domain}/{path}"
                        else:
                            auth_url = scan_repository_url
                    else:
                        # Public repository
                        auth_url = scan_repository_url

                    # Use dulwich to test the connection
                    porcelain.ls_remote(auth_url)

                    return Connection(is_connected=True)

                except Exception as e:
                    error_msg = str(e)
                    if "authentication" in error_msg.lower() or "401" in error_msg:
                        return Connection(
                            is_connected=False,
                            error="Authentication failed. Please check your access token.",
                        )
                    elif "404" in error_msg or "not found" in error_msg.lower():
                        return Connection(
                            is_connected=False,
                            error="Repository not found or not accessible.",
                        )
                    else:
                        return Connection(
                            is_connected=False,
                            error=f"Failed to connect to repository: {error_msg}",
                        )

        except Exception as error:
            if raise_on_exception:
                raise
            return Connection(
                is_connected=False,
                error=f"Unexpected error testing connection: {str(error)}",
            )
