from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ecs.ecs_client import ecs_client


def _check_port_in_range(port_range: str, target_port: int) -> bool:
    """
    Check if target port is in the port range.

    Port range format: "3389/3389" (from/to) or "3389" (single port)
    """
    if not port_range:
        return False

    try:
        if "/" in port_range:
            from_port, to_port = map(int, port_range.split("/"))
            return from_port <= target_port <= to_port
        else:
            port = int(port_range)
            return port == target_port
    except (ValueError, AttributeError):
        return False


def _is_public_cidr(cidr: str) -> bool:
    """Check if CIDR is public (0.0.0.0/0)."""
    return cidr == "0.0.0.0/0" or cidr == "::/0"


class ecs_securitygroup_restrict_rdp_internet(Check):
    """Check if security groups restrict RDP (port 3389) access from the internet."""

    def execute(self) -> list[Check_Report_AlibabaCloud]:
        findings = []
        check_port = 3389  # RDP port

        for sg_arn, security_group in ecs_client.security_groups.items():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=security_group
            )
            report.region = security_group.region
            report.resource_id = security_group.id
            report.resource_arn = security_group.arn

            # Check ingress rules for unrestricted access to RDP port
            has_unrestricted_access = False

            for ingress_rule in security_group.ingress_rules:
                # Check if rule allows traffic (policy == "accept")
                if ingress_rule.get("policy", "accept") != "accept":
                    continue

                # Check protocol (tcp for RDP)
                protocol = ingress_rule.get("ip_protocol", "").lower()
                if protocol not in ["tcp", "all"]:
                    continue

                # Check if source is public (0.0.0.0/0)
                source_cidr = ingress_rule.get("source_cidr_ip", "")
                if not _is_public_cidr(source_cidr):
                    continue

                # Check if port range includes RDP port
                port_range = ingress_rule.get("port_range", "")

                if protocol == "all":
                    # If protocol is "all", all ports are open
                    has_unrestricted_access = True
                    break
                elif _check_port_in_range(port_range, check_port):
                    has_unrestricted_access = True
                    break

            if has_unrestricted_access:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security group {security_group.name} ({security_group.id}) "
                    f"has Microsoft RDP port 3389 open to the internet (0.0.0.0/0)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security group {security_group.name} ({security_group.id}) "
                    f"does not have Microsoft RDP port 3389 open to the internet."
                )

            findings.append(report)

        return findings
