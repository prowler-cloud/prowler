"""Check if security lists allow ingress from 0.0.0.0/0 to port 22."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.network_client import network_client


class network_security_list_ingress_from_internet_to_ssh_port(Check):
    """Check if security lists allow ingress from 0.0.0.0/0 to port 22."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_list_ingress_from_internet_to_ssh_port check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for security_list in network_client.security_lists:
            has_public_ssh_access = False

            # Check ingress rules for public SSH access
            for rule in security_list.ingress_security_rules:
                if rule.get("source") == "0.0.0.0/0":
                    protocol = rule.get("protocol")
                    # Protocol 6 is TCP
                    if protocol == "6":
                        tcp_options = rule.get("tcp_options")
                        # If tcp_options is None, all TCP ports are allowed
                        if not tcp_options:
                            has_public_ssh_access = True
                            break
                        # If tcp_options exists, check destination port range
                        dst_port = tcp_options.get("destination_port_range")
                        if dst_port:
                            port_min = dst_port.get("min", 0)
                            port_max = dst_port.get("max", 0)
                            if port_min <= 22 <= port_max:
                                has_public_ssh_access = True
                                break
                        # If no destination port range specified, all ports are allowed
                        else:
                            has_public_ssh_access = True
                            break
                    # Protocol "all" or if protocol is not specified
                    elif protocol == "all" or not protocol:
                        has_public_ssh_access = True
                        break

            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=security_list,
                region=security_list.region,
                resource_name=security_list.display_name,
                resource_id=security_list.id,
                compartment_id=security_list.compartment_id,
            )

            if has_public_ssh_access:
                report.status = "FAIL"
                report.status_extended = f"Security list {security_list.display_name} allows ingress from 0.0.0.0/0 to port 22 (SSH)."
            else:
                report.status = "PASS"
                report.status_extended = f"Security list {security_list.display_name} does not allow ingress from 0.0.0.0/0 to port 22 (SSH)."

            findings.append(report)

        return findings
