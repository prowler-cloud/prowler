"""Pipeline Provider for scanning CI/CD pipelines with Poutine."""

import json
import subprocess
import sys
from typing import List

from alive_progress import alive_bar

from prowler.config.config import (
    default_config_file_path,
    load_and_validate_config_file,
)
from prowler.lib.check.models import CheckReportPipeline
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.pipeline.models import PipelineIdentityInfo


class PipelineProvider(Provider):
    """
    PipelineProvider scans CI/CD pipelines for security vulnerabilities using Poutine.

    Supports multiple pipeline platforms:
    - GitHub Actions
    - GitLab CI
    - Azure DevOps
    - Tekton (Pipelines as Code)

    Detects security issues such as:
    - Injection vulnerabilities
    - Insecure secret usage
    - Excessive permissions
    - Supply chain risks
    - Misconfigurations
    """

    _type: str = "pipeline"
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        scan_path: str = ".",
        repository_url: str = None,
        organization: str = None,
        platform: str = "github",  # github, gitlab, azure, tekton
        token: str = None,
        exclude_paths: List[str] = None,
        config_path: str = None,
        fixer_config: dict = None,
    ):
        """
        Initialize the Pipeline Provider.

        Args:
            scan_path: Local directory path to scan
            repository_url: Remote repository URL to scan
            organization: Organization name to scan all repos
            platform: CI/CD platform type (github, gitlab, azure, tekton)
            token: Authentication token for the platform
            exclude_paths: List of paths to exclude from scanning
            config_path: Path to Prowler config file
            fixer_config: Configuration for the fixer
        """
        logger.info("Initializing Pipeline Provider for CI/CD security scanning")

        self.scan_path = scan_path
        self.repository_url = repository_url
        self.organization = organization
        self.platform = platform
        self.token = token
        self.exclude_paths = exclude_paths or []

        # Provider type
        self._type = "pipeline"

        # Determine scan type
        if organization:
            scan_type = "organization"
        elif repository_url:
            scan_type = "repository"
        else:
            scan_type = "local"

        # Set authentication method
        if token:
            self._auth_method = f"{platform.capitalize()} Token"
        else:
            self._auth_method = "No auth (local scan only)"

        # Identity configuration
        self._identity = PipelineIdentityInfo(
            platform=platform,
            organization=organization or "",
            repository=repository_url or "",
            scan_type=scan_type,
        )
        self.audited_account = organization or "local-pipelines"
        self.region = "global"

        # Session is not needed for Pipeline provider
        self._session = None

        # Load configurations
        if config_path:
            self._audit_config = load_and_validate_config_file(self._type, config_path)
        else:
            self._audit_config = load_and_validate_config_file(
                self._type, default_config_file_path
            )

        self._fixer_config = fixer_config

        # Initialize audit metadata
        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=scan_type,
            account_name=platform,
            region="global",
            services_scanned=0,  # Pipeline doesn't use services
            expected_checks=[],  # Pipeline doesn't use checks
            completed_checks=0,
            audit_progress=0,
        )

        # Setup session (no-op for pipeline provider)
        self.setup_session()

        # Set the global provider
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
        """Pipeline provider doesn't need a session since it uses poutine directly"""
        return None

    def _process_poutine_finding(
        self, finding: dict, file_path: str
    ) -> CheckReportPipeline:
        """
        Process a poutine finding and create a CheckReportPipeline object.

        Args:
            finding: The finding object from poutine JSON output
            file_path: The path to the pipeline file

        Returns:
            CheckReportPipeline: The processed check report
        """
        try:
            # Extract finding details from poutine structure
            # Finding has: rule_id, purl, meta (with details, job, line, path, step)
            rule_id = (
                finding.get("rule_id", "unknown").replace("-", "_").replace(".", "_")
            )
            finding_id = f"pipeline_{rule_id}"

            # Get metadata
            meta = finding.get("meta", {})

            # For poutine, we need to get severity from the rules dict in the parent output
            # For now, use a default mapping based on rule_id
            severity_map = {
                "injection": "high",
                "debug_enabled": "low",
                "default_permissions_on_risky_events": "medium",
                "github_action_from_unverified_creator_used": "low",
                "if_always_true": "high",
                "job_all_secrets": "medium",
                "known_vulnerability_in_build_component": "high",
                "known_vulnerability_in_build_platform": "high",
                "pr_runs_on_self_hosted": "medium",
                "unpinnable_action": "low",
                "untrusted_checkout_exec": "critical",
                "unverified_script_exec": "high",
            }
            prowler_severity = severity_map.get(rule_id, "medium")

            # Extract location information from meta
            start_line = meta.get("line", 0)
            end_line = start_line  # Poutine doesn't provide end_line

            if start_line:
                if start_line == end_line:
                    line_range = f"line {start_line}"
                else:
                    line_range = f"lines {start_line}-{end_line}"
            else:
                line_range = "location unknown"

            # Get rule name from rule_id (use title case)
            rule_title = rule_id.replace("_", " ").title()

            # Build description from meta details
            details = meta.get("details", "")
            job = meta.get("job", "")
            step = meta.get("step", "")

            description = f"Security issue detected in pipeline: {rule_title}"
            if job:
                description += f" in job '{job}'"
            if step:
                description += f" at step {step}"
            if details:
                description += f". {details}"

            # Prepare metadata
            metadata = {
                "Provider": "pipeline",
                "CheckID": finding_id,
                "CheckTitle": rule_title,
                "CheckType": ["Security", "CI/CD"],
                "ServiceName": "pipeline",
                "SubServiceName": self.platform,
                "ResourceIdTemplate": "",
                "Severity": prowler_severity,
                "ResourceType": "Pipeline",
                "Description": description,
                "Risk": f"Potential {prowler_severity} severity security risk in CI/CD pipeline",
                "RelatedUrl": "https://boostsecurityio.github.io/poutine/rules/",
                "Remediation": {
                    "Code": {
                        "CLI": "",
                        "NativeIaC": "",
                        "Other": f"Review and fix the {rule_title.lower()} issue in your pipeline",
                        "Terraform": "",
                    },
                    "Recommendation": {
                        "Text": f"Fix the security issue at {line_range} in {file_path}",
                        "Url": f"https://boostsecurityio.github.io/poutine/rules/{rule_id}",
                    },
                },
                "Categories": ["security", "cicd"],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Create the report
            report = CheckReportPipeline(
                metadata=json.dumps(metadata), finding=finding, pipeline_path=file_path
            )

            report.resource_name = file_path
            report.resource_line_range = line_range
            report.status = "FAIL"
            report.status_extended = (
                f"Pipeline security issue found in {file_path} at {line_range}: "
                f"{rule_title}. "
                f"Severity: {prowler_severity}. "
                f"Details: {details if details else 'No additional details available'}"
            )

            return report

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def run(self) -> List[CheckReportPipeline]:
        """
        Execute poutine scan on the configured target.

        Returns:
            List of CheckReportPipeline objects with findings
        """
        try:
            if self.repository_url:
                return self._scan_repository(self.repository_url)
            elif self.organization:
                return self._scan_organization(self.organization)
            else:
                return self._scan_local(self.scan_path)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _scan_local(self, path: str) -> List[CheckReportPipeline]:
        """
        Scan a local directory for pipeline security issues.

        Args:
            path: Directory path to scan

        Returns:
            List of CheckReportPipeline objects
        """
        try:
            # Build poutine command
            poutine_command = ["poutine", "analyze_local", path, "--format", "json"]

            # Add exclude paths if provided
            for exclude_path in self.exclude_paths:
                poutine_command.extend(["--exclude", exclude_path])

            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Running pipeline security scan on {path} ..."
                    # Run poutine with JSON output
                    process = subprocess.run(
                        poutine_command,
                        capture_output=True,
                        text=True,
                    )
                    bar.title = "-> Scan completed!"
                except Exception as error:
                    bar.title = "-> Scan failed!"
                    raise error

            # Log poutine's stderr output
            if process.stderr:
                for line in process.stderr.strip().split("\n"):
                    if line.strip():
                        logger.debug(f"poutine: {line}")

            try:
                # Parse poutine JSON output
                if process.stdout:
                    output = json.loads(process.stdout)
                else:
                    logger.warning("No output returned from poutine scan")
                    return []

                # Check if poutine found any issues
                if not output:
                    logger.info("No security issues found in pipelines")
                    return []

            except json.JSONDecodeError as error:
                logger.warning(f"Failed to parse poutine output as JSON: {error}")
                logger.debug(f"Raw output: {process.stdout}")
                return []

            reports = []

            # Process poutine findings
            if isinstance(output, dict) and "findings" in output:
                # Poutine returns findings in a "findings" array
                for finding in output["findings"]:
                    # Extract path from meta field
                    file_path = finding.get("meta", {}).get("path", "unknown")
                    report = self._process_poutine_finding(finding, file_path)
                    reports.append(report)
            elif isinstance(output, list):
                # Alternative format: array of findings
                for finding in output:
                    file_path = finding.get("path", "unknown")
                    report = self._process_poutine_finding(finding, file_path)
                    reports.append(report)

            return reports

        except Exception as error:
            if "No such file or directory: 'poutine'" in str(error):
                logger.critical(
                    "poutine binary not found. Please install poutine from https://github.com/boostsecurityio/poutine "
                    "or use 'brew install poutine' on macOS"
                )
                sys.exit(1)
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _scan_repository(self, repository_url: str) -> List[CheckReportPipeline]:
        """
        Scan a remote repository for pipeline security issues.

        Args:
            repository_url: URL of the repository to scan

        Returns:
            List of CheckReportPipeline objects
        """
        try:
            # Extract org and repo from URL
            # Format: https://github.com/org/repo
            parts = repository_url.rstrip("/").split("/")
            if len(parts) >= 2:
                repo_path = f"{parts[-2]}/{parts[-1]}"
            else:
                logger.error(f"Invalid repository URL: {repository_url}")
                return []

            # Build poutine command
            poutine_command = ["poutine", "analyze_repo", repo_path, "--format", "json"]

            # Add token if provided
            if self.token:
                poutine_command.extend(["--token", self.token])

            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Scanning repository {repo_path} ..."
                    process = subprocess.run(
                        poutine_command,
                        capture_output=True,
                        text=True,
                    )
                    bar.title = "-> Scan completed!"
                except Exception as error:
                    bar.title = "-> Scan failed!"
                    raise error

            # Process output same as local scan
            return self._process_scan_output(process)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _scan_organization(self, organization: str) -> List[CheckReportPipeline]:
        """
        Scan all repositories in an organization.

        Args:
            organization: Organization name

        Returns:
            List of CheckReportPipeline objects
        """
        try:
            # Build poutine command
            poutine_command = [
                "poutine",
                "analyze_org",
                organization,
                "--format",
                "json",
            ]

            # Add token if provided
            if self.token:
                poutine_command.extend(["--token", self.token])

            with alive_bar(
                ctrl_c=False,
                bar="blocks",
                spinner="classic",
                stats=False,
                enrich_print=False,
            ) as bar:
                try:
                    bar.title = f"-> Scanning organization {organization} ..."
                    process = subprocess.run(
                        poutine_command,
                        capture_output=True,
                        text=True,
                    )
                    bar.title = "-> Scan completed!"
                except Exception as error:
                    bar.title = "-> Scan failed!"
                    raise error

            # Process output same as local scan
            return self._process_scan_output(process)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def _process_scan_output(self, process) -> List[CheckReportPipeline]:
        """Process the output from poutine scan."""
        # Log stderr
        if process.stderr:
            for line in process.stderr.strip().split("\n"):
                if line.strip():
                    logger.debug(f"poutine: {line}")

        try:
            # Parse JSON output
            if process.stdout:
                output = json.loads(process.stdout)
            else:
                logger.warning("No output returned from poutine scan")
                return []

            if not output:
                logger.info("No security issues found in pipelines")
                return []

        except json.JSONDecodeError as error:
            logger.warning(f"Failed to parse poutine output as JSON: {error}")
            return []

        reports = []

        # Process findings based on output format
        if isinstance(output, dict) and "findings" in output:
            for file_path, findings in output["findings"].items():
                for finding in findings:
                    report = self._process_poutine_finding(finding, file_path)
                    reports.append(report)
        elif isinstance(output, list):
            for finding in output:
                file_path = finding.get("path", "unknown")
                report = self._process_poutine_finding(finding, file_path)
                reports.append(report)

        return reports

    def print_credentials(self):
        """Print the credentials used for the scan."""
        if self.organization:
            scan_info = [[f"Organization: {self.organization}"]]
        elif self.repository_url:
            scan_info = [[f"Repository: {self.repository_url}"]]
        else:
            scan_info = [[f"Directory: {self.scan_path}"]]

        scan_info.append([f"Platform: {self.platform}"])
        scan_info.append([f"Authentication method: {self._auth_method}"])

        if self.exclude_paths:
            scan_info.append([f"Excluded paths: {', '.join(self.exclude_paths)}"])

        title = (
            "Scanning CI/CD pipelines for security issues:"
            if not self.organization and not self.repository_url
            else f"Scanning {self.platform.capitalize()} pipelines:"
        )

        print_boxes(scan_info, title)

    def test_connection(self):
        """Test the connection to the platform if using remote scanning."""
        if self.token and (self.repository_url or self.organization):
            # Could implement a test API call here
            return True
        return True
