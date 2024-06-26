from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kms.kms_client import kms_client


class kms_key_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for key in kms_client.keys:
            if (
                key.manager == "CUSTOMER" and key.state == "Enabled"
            ):  # only customer KMS have policies
                report = Check_Report_AWS(self.metadata())
                report.status = "PASS"
                report.status_extended = f"KMS key {key.id} is not exposed to Public."
                report.resource_id = key.id
                report.resource_arn = key.arn
                report.resource_tags = key.tags
                report.region = key.region
                # If the "Principal" element value is set to { "AWS": "*" } and the policy statement is not using any Condition clauses to filter the access, the selected AWS KMS master key is publicly accessible.
                if key.policy and "Statement" in key.policy:
                    for statement in key.policy["Statement"]:
                        if (
                            "Principal" in statement
                            and "*" == statement["Principal"]
                            and "Condition" not in statement
                        ):
                            report.status = "FAIL"
                            report.status_extended = (
                                f"KMS key {key.id} may be publicly accessible."
                            )
                        elif (
                            "Principal" in statement and "AWS" in statement["Principal"]
                        ):
                            if isinstance(statement["Principal"]["AWS"], str):
                                principals = [statement["Principal"]["AWS"]]
                            else:
                                principals = statement["Principal"]["AWS"]
                            for principal_arn in principals:
                                if (
                                    principal_arn == "*"
                                    and "Condition" not in statement
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = (
                                        f"KMS key {key.id} may be publicly accessible."
                                    )
                findings.append(report)
        return findings
