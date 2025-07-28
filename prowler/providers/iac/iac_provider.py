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
        frameworks: list[str] = ["all"],
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
        self.frameworks = frameworks
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

        # Mutelist (not needed for IAC since Checkov has its own mutelist logic)
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
        """IAC provider doesn't need a session since it uses Checkov directly"""
        return None

    def _process_check(self, finding: dict, check: dict, status: str) -> CheckReportIAC:
        """
        Process a single check (failed or passed) and create a CheckReportIAC object.

        Args:
            finding: The finding object from Checkov output
            check: The individual check data (failed_check or passed_check)
            status: The status of the check ("FAIL" or "PASS")

        Returns:
            CheckReportIAC: The processed check report
        """
        try:
            metadata_dict = {
                "Provider": "iac",
                "CheckID": check.get("check_id", ""),
                "CheckTitle": check.get("check_name", ""),
                "CheckType": ["Infrastructure as Code"],
                "ServiceName": finding["check_type"],
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": (
                    check.get("severity", "low").lower()
                    if check.get("severity")
                    else "low"
                ),
                "ResourceType": "iac",
                "Description": check.get("check_name", ""),
                "Risk": "",
                "RelatedUrl": (
                    check.get("guideline", "") if check.get("guideline") else ""
                ),
                "Remediation": {
                    "Code": {
                        "NativeIaC": "",
                        "Terraform": "",
                        "CLI": "",
                        "Other": "",
                    },
                    "Recommendation": {
                        "Text": "",
                        "Url": (
                            check.get("guideline", "") if check.get("guideline") else ""
                        ),
                    },
                },
                "Categories": [],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Convert metadata dict to JSON string
            metadata = json.dumps(metadata_dict)

            report = CheckReportIAC(metadata=metadata, finding=check)
            report.status = status
            report.resource_tags = check.get("entity_tags", {})
            report.status_extended = check.get("check_name", "")
            if status == "MUTED":
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
            reports = self.run_scan(scan_dir, self.frameworks, self.exclude_path)
        finally:
            if temp_dir:
                logger.info(f"Removing temporary directory {temp_dir}...")
                shutil.rmtree(temp_dir)

        return reports

    def run_scan(
        self, directory: str, frameworks: list[str], exclude_path: list[str]
    ) -> List[CheckReportIAC]:
        try:
            logger.info(f"Running IaC scan on {directory} ...")
            checkov_command = [
                "checkov",
                "-d",
                directory,
                "-o",
                "json",
                "-f",
                ",".join(frameworks),
            ]
            if exclude_path:
                checkov_command.extend(["-e", ",".join(exclude_path)])
            # Run Checkov with JSON output
            process = subprocess.run(
                checkov_command,
                capture_output=True,
                text=True,
            )
            # Log Checkov's error output if any
            if process.stderr:
                logger.error(process.stderr)

            try:
                output = json.loads(process.stdout)
                if not output:
                    logger.warning("No findings returned from Checkov scan")
                    return []
            except Exception as error:
                logger.critical(
                    f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                )
                sys.exit(1)

            reports = []

            # If only one framework has findings, the output is a dict, otherwise it's a list of dicts
            if isinstance(output, dict):
                output = [output]

            # Process all frameworks findings
            for finding in output:
                results = finding.get("results", {})

                # Process failed checks
                failed_checks = results.get("failed_checks", [])
                for failed_check in failed_checks:
                    report = self._process_check(finding, failed_check, "FAIL")
                    reports.append(report)

                # Process passed checks
                passed_checks = results.get("passed_checks", [])
                for passed_check in passed_checks:
                    report = self._process_check(finding, passed_check, "PASS")
                    reports.append(report)

                # Process skipped checks (muted)
                skipped_checks = results.get("skipped_checks", [])
                for skipped_check in skipped_checks:
                    report = self._process_check(finding, skipped_check, "MUTED")
                    reports.append(report)

            return reports

        except Exception as error:
            if "No such file or directory: 'checkov'" in str(error):
                logger.critical("Please, install checkov using 'pip install checkov'")
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
            f"Frameworks: {Fore.YELLOW}{', '.join(self.frameworks)}{Style.RESET_ALL}"
        )

        report_lines.append(
            f"Authentication method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}"
        )

        print_boxes(report_lines, report_title)
