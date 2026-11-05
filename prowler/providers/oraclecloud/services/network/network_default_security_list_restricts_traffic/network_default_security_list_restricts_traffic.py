"""Check if default security list restricts all traffic except ICMP within VCN."""

from ipaddress import ip_network

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
                unverifiable_rules = []

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
                    elif protocol and protocol != "1":
                        # Get VCN CIDR blocks to validate
                        vcn = None
                        for v in network_client.vcns:
                            if v.id == security_list.vcn_id:
                                vcn = v
                                break

                        source_type = rule.get("source_type")
                        if source_type not in (None, "CIDR_BLOCK"):
                            unverifiable_rules.append(
                                f"ingress from {source} with source type {source_type}"
                            )
                            continue

                        try:
                            if not isinstance(source, str):
                                raise ValueError("Source is not a CIDR string")
                            source_network = ip_network(source, strict=False)
                        except ValueError:
                            unverifiable_rules.append(
                                f"invalid ingress source {source}"
                            )
                            continue

                        if not vcn or not vcn.cidr_blocks:
                            unverifiable_rules.append("VCN CIDR blocks unavailable")
                            continue

                        is_within_vcn = False
                        invalid_vcn_cidr = False
                        for cidr in vcn.cidr_blocks:
                            try:
                                vcn_network = ip_network(cidr, strict=False)
                            except ValueError:
                                invalid_vcn_cidr = True
                                continue
                            if (
                                source_network.version == vcn_network.version
                                and source_network.subnet_of(vcn_network)
                            ):
                                is_within_vcn = True
                                break

                        if not is_within_vcn:
                            if invalid_vcn_cidr:
                                unverifiable_rules.append("invalid VCN CIDR block")
                            else:
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
                    if unverifiable_rules:
                        report.status_extended += f" Verify unassessed rules: {', '.join(unverifiable_rules)}."
                elif unverifiable_rules:
                    report.status = "MANUAL"
                    report.status_extended = f"Default security list {security_list.display_name} could not be fully assessed; verify {', '.join(unverifiable_rules)}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Default security list {security_list.display_name} restricts all traffic except ICMP within VCN."

                findings.append(report)

        return findings
