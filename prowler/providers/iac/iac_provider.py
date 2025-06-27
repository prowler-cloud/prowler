import json
import sys
from typing import List

from checkov.ansible.runner import Runner as AnsibleRunner
from checkov.argo_workflows.runner import Runner as ArgoWorkflowsRunner
from checkov.arm.runner import Runner as ArmRunner
from checkov.azure_pipelines.runner import Runner as AzurePipelinesRunner
from checkov.bicep.runner import Runner as BicepRunner
from checkov.bitbucket.runner import Runner as BitbucketRunner
from checkov.bitbucket_pipelines.runner import Runner as BitbucketPipelinesRunner
from checkov.cdk.runner import CdkRunner
from checkov.circleci_pipelines.runner import Runner as CircleciPipelinesRunner
from checkov.cloudformation.runner import Runner as CfnRunner
from checkov.common.output.record import Record
from checkov.common.output.report import Report
from checkov.common.runners.runner_registry import RunnerRegistry
from checkov.dockerfile.runner import Runner as DockerfileRunner
from checkov.github.runner import Runner as GithubRunner
from checkov.github_actions.runner import Runner as GithubActionsRunner
from checkov.gitlab.runner import Runner as GitlabRunner
from checkov.gitlab_ci.runner import Runner as GitlabCiRunner
from checkov.helm.runner import Runner as HelmRunner
from checkov.json_doc.runner import Runner as JsonDocRunner
from checkov.kubernetes.runner import Runner as K8sRunner
from checkov.kustomize.runner import Runner as KustomizeRunner
from checkov.openapi.runner import Runner as OpenapiRunner
from checkov.runner_filter import RunnerFilter
from checkov.sast.runner import Runner as SastRunner
from checkov.sca_image.runner import Runner as ScaImageRunner
from checkov.sca_package_2.runner import Runner as ScaPackage2Runner
from checkov.secrets.runner import Runner as SecretsRunner
from checkov.serverless.runner import Runner as ServerlessRunner
from checkov.terraform.runner import Runner as TerraformRunner
from checkov.terraform_json.runner import TerraformJsonRunner
from checkov.yaml_doc.runner import Runner as YamlDocRunner
from colorama import Fore, Style

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
        frameworks: list[str] = ["all"],
        exclude_path: list[str] = [],
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
    ):
        logger.info("Instantiating IAC Provider...")

        self.scan_path = scan_path
        self.frameworks = frameworks
        self.exclude_path = exclude_path
        self.region = "global"
        self.audited_account = "local-iac"
        self._session = None
        self._identity = "prowler"

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

    def _process_check(
        self, finding: Report, check: Record, status: str
    ) -> CheckReportIAC:
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
                "CheckID": check.check_id,
                "CheckTitle": check.check_name,
                "CheckType": ["Infrastructure as Code"],
                "ServiceName": finding.check_type,
                "SubServiceName": "",
                "ResourceIdTemplate": "",
                "Severity": (check.severity.lower() if check.severity else "low"),
                "ResourceType": finding.check_type,
                "Description": check.check_name,
                "Risk": "",
                "RelatedUrl": (check.guideline if check.guideline else ""),
                "Remediation": {
                    "Code": {
                        "NativeIaC": "",
                        "Terraform": "",
                        "CLI": "",
                        "Other": "",
                    },
                    "Recommendation": {
                        "Text": "",
                        "Url": (check.guideline if check.guideline else ""),
                    },
                },
                "Categories": [],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "",
            }

            # Convert metadata dict to JSON string
            metadata = json.dumps(metadata_dict)

            report = CheckReportIAC(metadata=metadata, resource=check)
            report.status = status
            report.resource_tags = check.entity_tags
            report.status_extended = check.check_name
            if status == "MUTED":
                report.muted = True
            return report
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
            )
            sys.exit(1)

    def run(self) -> List[CheckReportIAC]:
        return self.run_scan(self.scan_path, self.frameworks, self.exclude_path)

    def run_scan(
        self, directory: str, frameworks: list[str], exclude_path: list[str]
    ) -> List[CheckReportIAC]:
        try:
            logger.info(f"Running IaC scan on {directory}...")
            runners = [
                TerraformRunner(),
                CfnRunner(),
                K8sRunner(),
                ArmRunner(),
                ServerlessRunner(),
                DockerfileRunner(),
                YamlDocRunner(),
                OpenapiRunner(),
                SastRunner(),
                ScaImageRunner(),
                ScaPackage2Runner(),
                SecretsRunner(),
                AnsibleRunner(),
                ArgoWorkflowsRunner(),
                BitbucketRunner(),
                BitbucketPipelinesRunner(),
                CdkRunner(),
                CircleciPipelinesRunner(),
                GithubRunner(),
                GithubActionsRunner(),
                GitlabRunner(),
                GitlabCiRunner(),
                HelmRunner(),
                JsonDocRunner(),
                TerraformJsonRunner(),
                KustomizeRunner(),
                AzurePipelinesRunner(),
                BicepRunner(),
            ]
            runner_filter = RunnerFilter(
                framework=frameworks, excluded_paths=exclude_path
            )

            registry = RunnerRegistry("", runner_filter, *runners)
            checkov_reports = registry.run(root_folder=directory)

            reports: List[CheckReportIAC] = []
            for report in checkov_reports:

                for failed in report.failed_checks:
                    reports.append(self._process_check(report, failed, "FAIL"))

                for passed in report.passed_checks:
                    reports.append(self._process_check(report, passed, "PASS"))

                for skipped in report.skipped_checks:
                    reports.append(self._process_check(report, skipped, "MUTED"))

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
        if self.exclude_path:
            report_lines.append(
                f"Excluded paths: {Fore.YELLOW}{', '.join(self.exclude_path)}{Style.RESET_ALL}"
            )
        report_lines.append(
            f"Frameworks: {Fore.YELLOW}{', '.join(self.frameworks)}{Style.RESET_ALL}"
        )
        report_title = f"{Style.BRIGHT}Scanning local IaC directory:{Style.RESET_ALL}"
        print_boxes(report_lines, report_title)
