from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.network.network_client import network_client


class network_vpc_is_active(Check):
    """Check if E2E Networks VPCs are active."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for vpc in network_client.vpcs:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=vpc)
            report.status = "PASS"
            report.status_extended = f"VPC {vpc.name} is active."
            if not vpc.is_active or vpc.state != "Active":
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.name} is not active (state: {vpc.state})."
                )
            findings.append(report)
        return findings
