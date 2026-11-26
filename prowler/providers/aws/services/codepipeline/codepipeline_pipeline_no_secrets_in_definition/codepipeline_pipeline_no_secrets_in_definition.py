import json
from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.codepipeline.codepipeline_client import (
    codepipeline_client,
)


class codepipeline_pipeline_no_secrets_in_definition(Check):
    """Ensure CodePipeline pipeline definitions do not contain hardcoded secrets.

    Scans all stage action configurations for embedded credentials such as API keys,
    tokens, or passwords. Pipeline definitions are readable by many CI/CD roles and
    embedded credentials enable lateral movement.

    - PASS: No secrets are detected in any stage action configuration.
    - FAIL: A secret is detected in one or more stage action configurations.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the CodePipeline pipeline secrets check.

        Iterates over all discovered pipelines, scans each stage action
        configuration with detect-secrets, and reports any findings.

        Returns:
            List[Check_Report_AWS]: A list of report objects with check results.
        """
        findings = []
        secrets_ignore_patterns = codepipeline_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for pipeline in codepipeline_client.pipelines.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=pipeline)
            report.status = "PASS"
            report.status_extended = f"CodePipeline pipeline {pipeline.name} does not have secrets in its definition."
            secrets_found = []
            has_verified_secret = False

            for stage in pipeline.stages:
                for action in stage.actions:
                    if action.configuration:
                        detect_secrets_output = detect_secrets_scan(
                            data=json.dumps(action.configuration),
                            excluded_secrets=secrets_ignore_patterns,
                            detect_secrets_plugins=codepipeline_client.audit_config.get(
                                "detect_secrets_plugins"
                            ),
                        )
                        if detect_secrets_output:
                            for secret in detect_secrets_output:
                                secrets_found.append(
                                    f"{secret['type']} in stage {stage.name} action {action.name}"
                                )
                                if secret.get("is_verified"):
                                    has_verified_secret = True

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodePipeline pipeline {pipeline.name} has secrets in its definition: {', '.join(secrets_found)}."
                if has_verified_secret:
                    report.check_metadata.Severity = "critical"

            findings.append(report)

        return findings
