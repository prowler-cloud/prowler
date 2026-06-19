from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.cloudfunction.cloudfunction_client import (
    cloudfunction_client,
)


class cloudfunction_function_inside_vpc(Check):
    """Check that Cloud Functions are attached to a Serverless VPC Access connector.

    Verifies that each active Cloud Function has a `vpcConnector` configured so
    egress traffic flows through a private VPC network instead of the public
    internet. Functions in non-`ACTIVE` states are skipped because their network
    configuration is transient.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the VPC-connector check across all Cloud Functions.

        Returns:
            A list of `Check_Report_GCP` findings, one per active Cloud
            Function. Status is `PASS` when a `vpc_connector` is set and `FAIL`
            otherwise.
        """
        findings = []
        for function in cloudfunction_client.functions:
            if function.state != "ACTIVE":
                continue
            report = Check_Report_GCP(metadata=self.metadata(), resource=function)
            if function.vpc_connector:
                report.status = "PASS"
                report.status_extended = (
                    f"Cloud Function {function.name} is connected to a VPC via "
                    f"connector: {function.vpc_connector}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Cloud Function {function.name} is not connected to any VPC network."
            findings.append(report)
        return findings
