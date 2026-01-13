"""Check Ensure VCN flow logging is enabled for all subnets."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.logging.logging_client import logging_client
from prowler.providers.oraclecloud.services.network.network_client import network_client


class network_vcn_subnet_flow_logs_enabled(Check):
    """Check Ensure VCN flow logging is enabled for all subnets."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_vcn_subnet_flow_logs_enabled check."""
        findings = []

        for subnet in network_client.subnets:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=subnet,
                region=subnet.region,
                resource_name=subnet.display_name,
                resource_id=subnet.id,
                compartment_id=subnet.compartment_id,
            )

            # Check if subnet has flow logs enabled (either at VCN or subnet level)
            has_flow_logs = False

            # Check for VCN-level flow logs
            for log in logging_client.logs:
                if (
                    log.source_service == "flowlogs"
                    and log.source_resource
                    and subnet.vcn_id in log.source_resource
                    and log.region == subnet.region
                    and log.is_enabled
                ):
                    has_flow_logs = True
                    break

            # If no VCN-level logs, check for subnet-level flow logs
            if not has_flow_logs:
                for log in logging_client.logs:
                    if (
                        log.source_service == "flowlogs"
                        and log.source_resource
                        and subnet.id in log.source_resource
                        and log.region == subnet.region
                        and log.is_enabled
                    ):
                        has_flow_logs = True
                        break

            if has_flow_logs:
                report.status = "PASS"
                report.status_extended = (
                    f"Subnet {subnet.display_name} has flow logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Subnet {subnet.display_name} does not have flow logging enabled."
                )

            findings.append(report)

        return findings
