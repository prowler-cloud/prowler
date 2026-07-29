import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.codebuild.codebuild_client import codebuild_client


class codebuild_project_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        sensitive_vars_excluded = codebuild_client.audit_config.get(
            "excluded_sensitive_environment_variables", []
        )
        secrets_ignore_patterns = codebuild_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = codebuild_client.audit_config.get("secrets_validate", False)
        projects = list(codebuild_client.projects.values())

        # Collect every scannable plaintext variable across all projects and scan
        # them in batched Kingfisher invocations instead of one subprocess per
        # variable. Findings are keyed by (project index, variable index).
        def payloads():
            for project_index, project in enumerate(projects):
                if project.environment_variables:
                    for var_index, env_var in enumerate(project.environment_variables):
                        if (
                            env_var.type == "PLAINTEXT"
                            and env_var.name not in sensitive_vars_excluded
                        ):
                            yield (project_index, var_index), json.dumps(
                                {env_var.name: env_var.value}
                            )

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for project_index, project in enumerate(projects):
            report = Check_Report_AWS(metadata=self.metadata(), resource=project)
            report.status = "PASS"
            report.status_extended = f"CodeBuild project {project.name} does not have sensitive environment plaintext credentials."
            secrets_found = []
            all_secrets = []

            if scan_error and any(
                env_var.type == "PLAINTEXT"
                and env_var.name not in sensitive_vars_excluded
                for env_var in project.environment_variables or []
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan CodeBuild project {project.name} environment "
                    f"variables for secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            if project.environment_variables:
                for var_index, env_var in enumerate(project.environment_variables):
                    detect_secrets_output = batch_results.get(
                        (project_index, var_index)
                    )
                    if detect_secrets_output:
                        all_secrets.extend(detect_secrets_output)
                        secrets_found.extend(
                            [
                                f"{secret['type']} in variable {env_var.name}"
                                for secret in detect_secrets_output
                            ]
                        )

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = f"CodeBuild project {project.name} has sensitive environment plaintext credentials in variables: {', '.join(secrets_found)}."
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
