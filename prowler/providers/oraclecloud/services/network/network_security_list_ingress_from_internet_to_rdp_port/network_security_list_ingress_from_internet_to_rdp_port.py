"""Check Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.network_client import network_client


class network_security_list_ingress_from_internet_to_rdp_port(Check):
    """Check Ensure no security lists allow ingress from 0.0.0.0/0 to port 3389."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_list_ingress_from_internet_to_rdp_port check."""
        findings = []

        for security_list in network_client.security_lists:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=security_list,
                region=security_list.region,
                resource_name=security_list.display_name,
                resource_id=security_list.id,
                compartment_id=security_list.compartment_id,
            )

            # Check ingress rules for 0.0.0.0/0 to port 3389
            has_rdp_from_internet = False
            for rule in security_list.ingress_security_rules:
                if rule.get("source") == "0.0.0.0/0":
                    protocol = rule.get("protocol")
                    # Protocol 6 is TCP
                    if protocol == "6":
                        tcp_options = rule.get("tcp_options")
                        # If tcp_options is None, all TCP ports are allowed
                        if not tcp_options:
                            has_rdp_from_internet = True
                            break
                        # If tcp_options exists, check destination port range
                        dst_port = tcp_options.get("destination_port_range")
                        if dst_port:
                            port_min = dst_port.get("min", 0)
                            port_max = dst_port.get("max", 0)
                            if port_min <= 3389 <= port_max:
                                has_rdp_from_internet = True
                                break
                        # If no destination port range specified, all ports are allowed
                        else:
                            has_rdp_from_internet = True
                            break
                    # Protocol "all" or if protocol is not specified
                    elif protocol == "all" or not protocol:
                        has_rdp_from_internet = True
                        break

            if has_rdp_from_internet:
                report.status = "FAIL"
                report.status_extended = f"Security list {security_list.display_name} allows ingress from 0.0.0.0/0 to port 3389 (RDP)."
            else:
                report.status = "PASS"
                report.status_extended = f"Security list {security_list.display_name} does not allow ingress from 0.0.0.0/0 to port 3389 (RDP)."

            findings.append(report)

        return findings
