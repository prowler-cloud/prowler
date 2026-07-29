import fnmatch
import os
import tempfile
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_code(Check):
    def execute(self):
        findings = []
        if not awslambda_client.functions:
            return findings

        secrets_ignore_patterns = awslambda_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        # Glob patterns of file names inside the deployment package to skip
        # when scanning for secrets (e.g. "*.deps.json" for .NET Lambdas).
        secrets_ignore_files = (
            awslambda_client.audit_config.get("secrets_ignore_files", []) or []
        )
        validate = awslambda_client.audit_config.get("secrets_validate", False)

        # Scan files of every function's package in batched
        # Kingfisher invocations instead of one subprocess per file per function.
        # Each package is extracted one at a time and its files are
        # read (byte-faithfully via latin-1) before the extraction is released,
        # so only a single package is on disk at a time. Findings are keyed by
        # (function index, package-relative file name) so they can be grouped
        # back per function.
        functions_with_code = []

        def code_payloads():
            for function, function_code in awslambda_client._get_function_code():
                if not function_code:
                    continue
                index = len(functions_with_code)
                functions_with_code.append(function)
                with tempfile.TemporaryDirectory() as tmp_dir_name:
                    function_code.code_zip.extractall(tmp_dir_name)
                    for root, _, files in os.walk(tmp_dir_name):
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            relative_file_path = os.path.relpath(
                                file_path, tmp_dir_name
                            )
                            if any(
                                fnmatch.fnmatch(relative_file_path, pattern)
                                for pattern in secrets_ignore_files
                            ):
                                continue
                            try:
                                with open(file_path, "rb") as code_file:
                                    content = code_file.read().decode("latin-1")
                            except Exception:
                                continue
                            yield (index, relative_file_path), content

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                code_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        if scan_error:
            # The scan failed before any function's code could be cleared. Report
            # MANUAL for every function rather than risk a false PASS.
            for function in awslambda_client.functions.values():
                report = Check_Report_AWS(metadata=self.metadata(), resource=function)
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Lambda function {function.name} code for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
            return findings

        findings_by_function = defaultdict(dict)
        for (index, file_name), file_findings in batch_results.items():
            findings_by_function[index][file_name] = file_findings

        for index, function in enumerate(functions_with_code):
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} code."
            )

            files_with_secrets = findings_by_function.get(index)
            if files_with_secrets:
                all_secrets = []
                secrets_findings = []
                for file_name, file_findings in files_with_secrets.items():
                    all_secrets.extend(file_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in file_findings
                    )
                    secrets_findings.append(f"{file_name}: {secrets_string}")

                final_output_string = "; ".join(secrets_findings)
                report.status = "FAIL"
                report.status_extended = f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} found in Lambda function {function.name} code -> {final_output_string}."
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
