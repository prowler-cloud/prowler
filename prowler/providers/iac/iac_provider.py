import json
import shutil
import subprocess
import sys
import tempfile
from os import environ
from typing import List

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
from prowler.providers.common.models import Audit_Metadata
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
        self.region = "global"
        self.audited_account = "local-iac"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"

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
                "Risk": "",
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
            return report
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _clone_repository(
        self,
        repository_url: str,
        github_username: str = None,
        personal_access_token: str = None,
        oauth_app_token: str = None,
    ) -> str:
        """
        Clone a git repository to a temporary directory, supporting GitHub authentication.
        """
        try:
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
                f"Cloning repository {repository_url} into {temporary_directory}..."
            )
            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Cloning {repository_url}..."
                    porcelain.clone(repository_url, temporary_directory, depth=1)
                    bar.title = "-> Repository cloned successfully!"
                except Exception as clone_error:
                    bar.title = "-> Cloning failed!"
                    raise clone_error
            return temporary_directory
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )

    def run(self) -> List[CheckReportIAC]:
        temp_dir = None
        if self.scan_repository_url:
            scan_dir = temp_dir = self._clone_repository(
                self.scan_repository_url,
                getattr(self, "github_username", None),
                getattr(self, "personal_access_token", None),
                getattr(self, "oauth_app_token", None),
            )
        else:
            scan_dir = self.scan_path

        try:
            reports = self.run_scan(scan_dir, self.scanners, self.exclude_path)
        finally:
            if temp_dir:
                logger.info(f"Removing temporary directory {temp_dir}...")
                shutil.rmtree(temp_dir)

        return reports

    def run_scan(
        self, directory: str, scanners: list[str], exclude_path: list[str]
    ) -> List[CheckReportIAC]:
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
                output = json.loads(process.stdout)["Results"]

                if not output:
                    logger.warning("No findings returned from Trivy scan")
                    return []
            except Exception as error:
                logger.critical(
                    f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                )
                sys.exit(1)

            reports = []

            # Process all trivy findings
            for finding in output:

                # Process Misconfigurations
                for misconfiguration in finding.get("Misconfigurations", []):
                    report = self._process_finding(
                        misconfiguration, finding["Target"], finding["Type"]
                    )
                    reports.append(report)
                # Process Vulnerabilities
                for vulnerability in finding.get("Vulnerabilities", []):
                    report = self._process_finding(
                        vulnerability, finding["Target"], finding["Type"]
                    )
                    reports.append(report)
                # Process Secrets
                for secret in finding.get("Secrets", []):
                    report = self._process_finding(
                        secret, finding["Target"], finding["Class"]
                    )
                    reports.append(report)
                # Process Licenses
                for license in finding.get("Licenses", []):
                    report = self._process_finding(
                        license, finding["Target"], finding["Type"]
                    )
                    reports.append(report)

            return reports

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
