from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudfunction.cloudfunction_client import (
    cloudfunction_client,
)


class cloudfunction_function_not_publicly_accessible(Check):
    """Check that Cloud Functions do not grant invocation rights to all users.

    Verifies that no active Cloud Function has an IAM binding granting access
    to `allUsers` or `allAuthenticatedUsers`. Non-`ACTIVE` functions are
    skipped because their IAM bindings are transient.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the public-access check across all Cloud Functions.

        Returns:
            A list of `Check_Report_GCP` findings, one per active Cloud
            Function. Status is `FAIL` when the function is invokable by
            `allUsers` or `allAuthenticatedUsers` and `PASS` otherwise.
        """
        findings = []
        for function in cloudfunction_client.functions:
            if function.state != "ACTIVE":
                continue
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=function,
                resource_id=function.name,
            )
            if function.publicly_accessible:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cloud Function {function.name} is publicly invocable "
                    f"(allUsers or allAuthenticatedUsers IAM binding detected)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Cloud Function {function.name} is not publicly accessible."
                )
            findings.append(report)
        return findings
