import os
import tempfile

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_code(Check):
    def execute(self):
        findings = []
        for function, function_code in awslambda_client.__get_function_code__():
            if function_code:
                report = Check_Report_AWS(self.metadata())
                report.region = function.region
                report.resource_id = function.name
                report.resource_arn = function.arn
                report.resource_tags = function.tags

                report.status = "PASS"
                report.status_extended = (
                    f"No secrets found in Lambda function {function.name} code."
                )
                with tempfile.TemporaryDirectory() as tmp_dir_name:
                    function_code.code_zip.extractall(tmp_dir_name)
                    # List all files
                    files_in_zip = next(os.walk(tmp_dir_name))[2]
                    secrets_findings = []
                    for file in files_in_zip:
                        secrets = SecretsCollection()
                        with default_settings():
                            secrets.scan_file(f"{tmp_dir_name}/{file}")
                        detect_secrets_output = secrets.json()
                        if detect_secrets_output:
                            for (
                                file_name
                            ) in (
                                detect_secrets_output.keys()
                            ):  # Appears that only 1 file is being scanned at a time, so could rework this
                                output_file_name = file_name.replace(
                                    f"{tmp_dir_name}/", ""
                                )
                                secrets_string = ", ".join(
                                    [
                                        f"{secret['type']} on line {secret['line_number']}"
                                        for secret in detect_secrets_output[file_name]
                                    ]
                                )
                                secrets_findings.append(
                                    f"{output_file_name}: {secrets_string}"
                                )

                    if secrets_findings:
                        final_output_string = "; ".join(secrets_findings)
                        report.status = "FAIL"
                        # report.status_extended = f"Potential {'secrets' if len(secrets_findings)>1 else 'secret'} found in Lambda function {function.name} code. {final_output_string}."
                        if len(secrets_findings) > 1:
                            report.status_extended = f"Potential secrets found in Lambda function {function.name} code -> {final_output_string}."
                        else:
                            report.status_extended = f"Potential secret found in Lambda function {function.name} code -> {final_output_string}."
                        # break // Don't break as there may be additional findings

                findings.append(report)

        return findings
