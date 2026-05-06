from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudfunction.cloudfunction_client import (
    cloudfunction_client,
)


class cloudfunction_function_inside_vpc(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for function in cloudfunction_client.functions:
            if function.state != "ACTIVE":
                continue
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=function,
                resource_id=function.name,
                location=function.location,
            )
            if function.vpc_connector:
                report.status = "PASS"
                report.status_extended = (
                    f"Cloud Function {function.name} is connected to a VPC via "
                    f"connector '{function.vpc_connector}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cloud Function {function.name} is not connected to any VPC network."
                )
            findings.append(report)
        return findings
