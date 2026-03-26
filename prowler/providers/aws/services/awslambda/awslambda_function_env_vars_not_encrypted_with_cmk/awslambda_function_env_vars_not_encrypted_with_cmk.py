from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_env_vars_not_encrypted_with_cmk(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            if not function.environment:
                report.status = "PASS"
                report.status_extended = (
                    f"Lambda function {function.name} has no environment variables."
                )
            elif function.kms_key_arn:
                report.status = "PASS"
                report.status_extended = (
                    f"Lambda function {function.name} environment variables are "
                    f"encrypted with KMS key {function.kms_key_arn}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Lambda function {function.name} has environment variables "
                    f"but they are not encrypted with a customer-managed KMS key."
                )
            findings.append(report)
        return findings
