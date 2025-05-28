import json
import subprocess
import sys
from typing import List

from colorama import Fore, Style

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
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating IAC Provider...")

        self.scan_path = scan_path
        self.region = "global"
        self.audited_account = "local-iac"
        self._session = None
        self._identity = "prowler"

        self._audit_config = config_content if config_content else {}
        self._fixer_config = fixer_config
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
        # Get severity and ensure it's a valid string
        severity = finding.get("severity", "low")
        if severity is None:
            severity = "low"
        severity = str(severity).lower()

        # Create a basic metadata structure for the check
        metadata_dict = {
            "Provider": "iac",
            "CheckID": check.get("check_id", ""),
            "CheckTitle": check.get("check_name", ""),
            "CheckType": ["Infrastructure as Code"],
            "ServiceName": "iac",
            "SubServiceName": "",
            "ResourceIdTemplate": "",
            "Severity": severity,
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
            "GCPProject": check.get("project_id", ""),
        }

        # Convert metadata dict to JSON string
        metadata = json.dumps(metadata_dict)

        report = CheckReportIAC(metadata=metadata, finding=check)
        report.status = status
        return report

    def run(self) -> List[CheckReportIAC]:
        return self.run_scan(self.scan_path)

    def run_scan(self, directory: str) -> List[CheckReportIAC]:
        try:
            logger.info(f"Running IaC scan on {directory}...")

            # Run Checkov with JSON output
            process = subprocess.run(
                ["checkov", "-d", directory, "-o", "json"],
                capture_output=True,
                text=True,
            )

            try:
                output = json.loads(process.stdout)
                if not output:
                    logger.warning("No findings returned from Checkov scan")
                    return []
            except json.JSONDecodeError:
                logger.error("Failed to parse IaC scan output as JSON")
                return []

            reports = []

            # Process all findings
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

            return reports

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def print_credentials(self):
        report_lines = [
            f"Directory: {Fore.YELLOW}{self.scan_path}{Style.RESET_ALL}",
        ]
        report_title = f"{Style.BRIGHT}Scanning local IaC directory:{Style.RESET_ALL}"
        print_boxes(report_lines, report_title)
