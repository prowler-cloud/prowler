from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_using_cross_account_layers(Check):
    def execute(self):
        findings = []
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)
            cross_account_layers = [
                layer
                for layer in function.layers
                if layer.account_id != awslambda_client.audited_account
            ]
            if not function.layers:
                report.status = "PASS"
                report.status_extended = (
                    f"Lambda function {function.name} does not use any layers."
                )
            elif cross_account_layers:
                report.status = "FAIL"
                layer_arns = ", ".join(layer.arn for layer in cross_account_layers)
                report.status_extended = (
                    f"Lambda function {function.name} uses cross-account "
                    f"layer(s): {layer_arns}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Lambda function {function.name} only uses layers "
                    f"from the same account ({awslambda_client.audited_account})."
                )
            findings.append(report)
        return findings
