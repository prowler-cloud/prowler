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
from prowler.lib.check.models import CheckReportGithubAction, CheckMetadata
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class GithubActionProvider(Provider):
    _type: str = "github_action"
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        workflow_path: str = ".",
        repository_url: str = None,
        exclude_workflows: list[str] = [],
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        github_username: str = None,
        personal_access_token: str = None,
        oauth_app_token: str = None,
    ):
        logger.info("Instantiating GitHub Action Provider...")

        self.workflow_path = workflow_path
        self.repository_url = repository_url
        self.exclude_workflows = exclude_workflows
        self.region = "global"
        self.audited_account = "github-actions"
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"

        if repository_url:
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

        # Mutelist (not needed for GitHub Actions since zizmor has its own ignore logic)
        self._mutelist = None

        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=self.audited_account,
            account_name="github_action",
            region=self.region,
            services_scanned=0,  # GitHub Actions doesn't use services
            expected_checks=[],  # GitHub Actions doesn't use checks
            completed_checks=0,  # GitHub Actions doesn't use checks
            audit_progress=0,  # GitHub Actions doesn't use progress tracking
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
        """GitHub Action provider doesn't need a session since it uses zizmor directly"""
        return None

    def _process_zizmor_finding(
        self, finding: dict, workflow_file: str, location: dict
    ) -> CheckReportGithubAction:
        """
        Process a zizmor finding with the new JSON structure.
        
        Args:
            finding: The finding object from zizmor output
            workflow_file: The path to the workflow file
            location: The specific location object for this finding
            
        Returns:
            CheckReportGithubAction: The processed check report
        """
        try:
            # Extract location details
            concrete_location = location.get("concrete", {}).get("location", {})
            start = concrete_location.get("start_point", {})
            end = concrete_location.get("end_point", {})
            
            # Format line range
            if start and end:
                if start.get("row") == end.get("row"):
                    line_range = f"line {start.get('row', 'unknown')}"
                else:
                    line_range = f"lines {start.get('row', 'unknown')}-{end.get('row', 'unknown')}"
            else:
                line_range = "location unknown"
            
            # Get determinations (severity/confidence)
            determinations = finding.get("determinations", {})
            severity = determinations.get("severity", "Unknown").lower()
            confidence = determinations.get("confidence", "Unknown")
            
            # Map zizmor severity to Prowler severity
            severity_map = {
                "critical": "critical",
                "high": "high", 
                "medium": "medium",
                "low": "low",
                "informational": "informational",
                "unknown": "medium"
            }
            prowler_severity = severity_map.get(severity, "medium")
            
            # Create CheckReport
            finding_id = f"githubaction_{finding.get('ident', 'unknown').replace('-', '_')}"
            
            # Prepare metadata dict
            metadata = {
                "Provider": "github_action",
                "CheckID": finding_id,
                "CheckTitle": finding.get("desc", "Unknown GitHub Actions Security Issue"),
                "CheckType": ["Security"],
                "ServiceName": "githubaction",
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": prowler_severity,
                "ResourceType": "GitHubActionsWorkflow",
                "Description": finding.get("desc", "Security issue detected in GitHub Actions workflow"),
                "Risk": location.get("symbolic", {}).get("annotation", "Security risk in workflow"),
                "RelatedUrl": finding.get("url", "https://docs.zizmor.sh/"),
                "Remediation": {
                    "Code": {
                        "CLI": "",
                        "NativeIaC": "",
                        "Other": "Review and fix the security issue in your GitHub Actions workflow",
                        "Terraform": ""
                    },
                    "Recommendation": {
                        "Text": f"Review the security issue at {line_range} in {workflow_file}. {finding.get('desc', '')}",
                        "Url": finding.get("url", "https://docs.zizmor.sh/")
                    }
                },
                "Categories": ["security"],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": ""
            }
            
            # Create the report with metadata as JSON string and finding
            report = CheckReportGithubAction(
                metadata=json.dumps(metadata),
                finding=finding,
                workflow_path=workflow_file
            )
            
            report.resource_name = workflow_file
            report.resource_line_range = line_range
            report.status = "FAIL"
            report.status_extended = (
                f"GitHub Actions security issue found in {workflow_file} at {line_range}: "
                f"{finding.get('desc', 'Unknown issue')}. "
                f"Confidence: {confidence}. "
                f"Details: {location.get('symbolic', {}).get('annotation', 'No details available')}"
            )
            
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
            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Cloning {original_url}..."
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

    def run(self) -> List[CheckReportGithubAction]:
        temp_dir = None
        if self.repository_url:
            scan_dir = temp_dir = self._clone_repository(
                self.repository_url,
                getattr(self, "github_username", None),
                getattr(self, "personal_access_token", None),
                getattr(self, "oauth_app_token", None),
            )
        else:
            scan_dir = self.workflow_path

        try:
            reports = self.run_scan(scan_dir, self.exclude_workflows)
        finally:
            if temp_dir:
                logger.info(f"Removing temporary directory {temp_dir}...")
                shutil.rmtree(temp_dir)

        return reports

    def run_scan(
        self, directory: str, exclude_workflows: list[str]
    ) -> List[CheckReportGithubAction]:
        try:
            logger.info(f"Running GitHub Actions security scan on {directory} ...")
            
            # Build zizmor command
            zizmor_command = [
                "zizmor",
                directory,
                "--format",
                "json",
            ]
            
            # Add exclude patterns if provided
            for exclude_pattern in exclude_workflows:
                zizmor_command.extend(["--exclude", exclude_pattern])
                
            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Running GitHub Actions security scan on {directory} ..."
                    # Run zizmor with JSON output
                    process = subprocess.run(
                        zizmor_command,
                        capture_output=True,
                        text=True,
                    )
                    bar.title = "-> Scan completed!"
                except Exception as error:
                    bar.title = "-> Scan failed!"
                    raise error
                    
            # Log zizmor's stderr output
            if process.stderr:
                for line in process.stderr.strip().split("\n"):
                    if line.strip():
                        logger.debug(f"zizmor: {line}")

            try:
                # Parse zizmor JSON output
                if process.stdout:
                    output = json.loads(process.stdout)
                else:
                    logger.warning("No output returned from zizmor scan")
                    return []
                    
                # zizmor returns an array of findings directly
                if not output or (isinstance(output, list) and len(output) == 0):
                    logger.info("No security issues found in GitHub Actions workflows")
                    return []
                    
            except json.JSONDecodeError as error:
                # zizmor might not output JSON for certain cases
                logger.warning(f"Failed to parse zizmor output as JSON: {error}")
                logger.debug(f"Raw output: {process.stdout}")
                return []
            except Exception as error:
                logger.critical(
                    f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
                )
                sys.exit(1)

            reports = []

            # zizmor returns an array of findings, each with its own location info
            for finding in output:
                # Extract workflow file from the finding's location
                if "locations" in finding and finding["locations"]:
                    for location in finding["locations"]:
                        if "symbolic" in location and "key" in location["symbolic"]:
                            key = location["symbolic"]["key"]
                            if "Local" in key:
                                workflow_file = key["Local"]["given_path"]
                                report = self._process_zizmor_finding(finding, workflow_file, location)
                                reports.append(report)

            return reports

        except Exception as error:
            if "No such file or directory: 'zizmor'" in str(error):
                logger.critical(
                    "zizmor binary not found. Please install zizmor from https://github.com/woodruffw/zizmor "
                    "or use your system package manager (e.g., 'cargo install zizmor' with Rust cargo)"
                )
                sys.exit(1)
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def print_credentials(self):
        if self.repository_url:
            report_title = (
                f"{Style.BRIGHT}Scanning remote GitHub repository:{Style.RESET_ALL}"
            )
            report_lines = [
                f"Repository: {Fore.YELLOW}{self.repository_url}{Style.RESET_ALL}",
            ]
        else:
            report_title = (
                f"{Style.BRIGHT}Scanning local GitHub Actions workflows:{Style.RESET_ALL}"
            )
            report_lines = [
                f"Directory: {Fore.YELLOW}{self.workflow_path}{Style.RESET_ALL}",
            ]

        if self.exclude_workflows:
            report_lines.append(
                f"Excluded workflows: {Fore.YELLOW}{', '.join(self.exclude_workflows)}{Style.RESET_ALL}"
            )

        report_lines.append(
            f"Authentication method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}"
        )

        print_boxes(report_lines, report_title)