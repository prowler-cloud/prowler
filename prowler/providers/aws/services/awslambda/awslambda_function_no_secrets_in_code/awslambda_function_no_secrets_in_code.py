import fnmatch
import os
import tempfile

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_code(Check):
    def execute(self):
        findings = []
        if awslambda_client.functions:
            secrets_ignore_patterns = awslambda_client.audit_config.get(
                "secrets_ignore_patterns", []
            )
            # Glob patterns of file names inside the deployment package to skip
            # when scanning for secrets (e.g. "*.deps.json" for .NET Lambdas).
            secrets_ignore_files = (
                awslambda_client.audit_config.get("secrets_ignore_files", []) or []
            )
            for function, function_code in awslambda_client._get_function_code():
                if function_code:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=function
                    )

                    report.status = "PASS"
                    report.status_extended = (
                        f"No secrets found in Lambda function {function.name} code."
                    )
                    with tempfile.TemporaryDirectory() as tmp_dir_name:
                        function_code.code_zip.extractall(tmp_dir_name)
                        secrets_findings = []
                        for root, _, files in os.walk(tmp_dir_name):
                            for file in files:
                                file_path = os.path.join(root, file)
                                relative_file_path = os.path.relpath(
                                    file_path, tmp_dir_name
                                )
                                # Skip files whose relative path matches an ignore pattern
                                # so known false-positive files (e.g. .NET
                                # *.deps.json) do not raise spurious findings.
                                if any(
                                    fnmatch.fnmatch(relative_file_path, pattern)
                                    for pattern in secrets_ignore_files
                                ):
                                    continue
                                detect_secrets_output = detect_secrets_scan(
                                    file=file_path,
                                    excluded_secrets=secrets_ignore_patterns,
                                    detect_secrets_plugins=awslambda_client.audit_config.get(
                                        "detect_secrets_plugins",
                                    ),
                                )
                                if detect_secrets_output:
                                    for (
                                        secret
                                    ) in (
                                        detect_secrets_output
                                    ):  # Appears that only 1 file is being scanned at a time, so could rework this
                                        output_file_name = os.path.relpath(
                                            secret["filename"], tmp_dir_name
                                        )
                                        secrets_string = ", ".join(
                                            [
                                                f"{secret['type']} on line {secret['line_number']}"
                                                for secret in detect_secrets_output
                                            ]
                                        )
                                        secrets_findings.append(
                                            f"{output_file_name}: {secrets_string}"
                                        )

                        if secrets_findings:
                            final_output_string = "; ".join(secrets_findings)
                            report.status = "FAIL"
                            report.status_extended = f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} found in Lambda function {function.name} code -> {final_output_string}."

                    findings.append(report)

        return findings
