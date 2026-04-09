from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class ec2_securitygroup_exposes_ports_80_443_only(Check):
    def execute(self):
        findings = []
        allowed_ports = [80, 443]

        security_group_map = {sg.id: sg for sg in ec2_client.security_groups.values()}
        for instance in ec2_client.instances:
            for sg in instance.security_groups:
                security_group = security_group_map.get(sg)
                if security_group:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
                    report.resource_tags = instance.tags
                    report.status = "PASS"
                    report.status_extended = f"Security group {security_group.name} ({security_group.id}) exposes only ports 80 and 443 to the public internet."

                    # Fail if ingress_rules is empty
                    if not security_group.ingress_rules:
                        report.status = "FAIL"
                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) has no ingress rules."
                    else:
                        for ingress_rule in security_group.ingress_rules:
                            protocol = ingress_rule["IpProtocol"]
                            if protocol.lower() != "icmp":
                                for port in range(ingress_rule["FromPort"], ingress_rule["ToPort"] + 1):
                                    if port not in allowed_ports or not check_security_group(ingress_rule, protocol, ports=[port], any_address=True):
                                        # If a port fails the check, mark as FAIL and break
                                        report.status = "FAIL"
                                        report.status_extended = f"Security group {security_group.name} ({security_group.id}) exposes unauthorized ports to the public internet."
                                        break
                                if report.status == "FAIL":
                                    break  # Exit the loop early if a failure is detected

                    findings.append(report)

        return findings
