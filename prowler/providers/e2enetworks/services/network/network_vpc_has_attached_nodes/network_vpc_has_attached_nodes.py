from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.network.network_client import network_client


class network_vpc_has_attached_nodes(Check):
    """Check if E2E Networks VPCs have attached nodes."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for vpc in network_client.vpcs:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=vpc)
            report.status = "PASS"
            report.status_extended = (
                f"VPC {vpc.name} has {vpc.vm_count} attached node(s)."
            )
            if vpc.vm_count <= 0:
                report.status = "FAIL"
                report.status_extended = f"VPC {vpc.name} has no attached nodes."
            findings.append(report)
        return findings
