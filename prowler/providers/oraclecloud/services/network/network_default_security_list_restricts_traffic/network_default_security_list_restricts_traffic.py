"""Check if default security list restricts all traffic except ICMP within VCN."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.network_client import network_client


class network_default_security_list_restricts_traffic(Check):
    """Check if default security list restricts all traffic except ICMP within VCN."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_default_security_list_restricts_traffic check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for security_list in network_client.security_lists:
            # Only check default security lists
            if security_list.is_default:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=security_list,
                    region=security_list.region,
                    resource_name=security_list.display_name,
                    resource_id=security_list.id,
                    compartment_id=security_list.compartment_id,
                )

                # Check if default security list has overly permissive rules
                has_permissive_rules = False
                permissive_rule_details = []

                # Check ingress rules
                for rule in security_list.ingress_security_rules:
                    source = rule.get("source")
                    protocol = rule.get("protocol")

                    # Protocol 1 is ICMP, which is allowed within VCN
                    if protocol == "1":
                        continue

                    # Check if source is from internet (0.0.0.0/0)
                    if source == "0.0.0.0/0":
                        has_permissive_rules = True
                        permissive_rule_details.append(
                            f"ingress from 0.0.0.0/0 with protocol {protocol}"
                        )
                    # Check if source is not within VCN CIDR (should only allow VCN traffic)
                    # For simplicity, we flag any non-ICMP rule as potentially permissive
                    # In production, you'd want to compare against the VCN CIDR blocks
                    elif protocol and protocol != "1":
                        # Get VCN CIDR blocks to validate
                        vcn = None
                        for v in network_client.vcns:
                            if v.id == security_list.vcn_id:
                                vcn = v
                                break

                        if vcn:
                            # Check if source is within VCN CIDR
                            is_within_vcn = False
                            for cidr in vcn.cidr_blocks:
                                if source and source.startswith(cidr.split("/")[0]):
                                    is_within_vcn = True
                                    break

                            if not is_within_vcn:
                                has_permissive_rules = True
                                permissive_rule_details.append(
                                    f"ingress from {source} with protocol {protocol}"
                                )

                # Check egress rules - should also be restricted
                for rule in security_list.egress_security_rules:
                    destination = rule.get("destination")
                    protocol = rule.get("protocol")

                    # Protocol 1 is ICMP, which is allowed within VCN
                    if protocol == "1":
                        continue

                    # Check if destination is to internet (0.0.0.0/0) for non-ICMP
                    if destination == "0.0.0.0/0" and protocol and protocol != "1":
                        has_permissive_rules = True
                        permissive_rule_details.append(
                            f"egress to 0.0.0.0/0 with protocol {protocol}"
                        )

                if has_permissive_rules:
                    report.status = "FAIL"
                    report.status_extended = f"Default security list {security_list.display_name} has permissive rules: {', '.join(permissive_rule_details)}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Default security list {security_list.display_name} restricts all traffic except ICMP within VCN."

                findings.append(report)

        return findings
