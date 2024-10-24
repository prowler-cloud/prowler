from typing import List
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_sg_open_to_authorized_ports(Check):
    authorized_ports: List[int] = [22, 80, 443]  # Define your authorized ports here

    def execute(self):
        findings = []
        for sg in vpc_client.security_groups:
            unauthorized_ports_found = False
            for rule in sg.ingress_rules:
                for ip_range in rule.get("IpRanges", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    if from_port is None or to_port is None:
                        continue
                    if (
                        from_port not in self.authorized_ports
                        or to_port not in self.authorized_ports
                    ):
                        unauthorized_ports_found = True
                        report = Check_Report_AWS(self.metadata())
                        report.region = sg.region
                        report.resource_tags = sg.tags
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Security Group {sg.name if sg.name else sg.id} allows unauthorized port range "
                            f"{from_port}-{to_port} from {ip_range['CidrIp']}."
                        )
                        report.resource_id = sg.id
                        report.resource_arn = sg.arn
                        findings.append(report)

            if not unauthorized_ports_found:
                report = Check_Report_AWS(self.metadata())
                report.region = sg.region
                report.resource_tags = sg.tags
                report.status = "PASS"
                report.status_extended = f"Security Group {sg.name if sg.name else sg.id} only allows authorized ports."
                report.resource_id = sg.id
                report.resource_arn = sg.arn
                findings.append(report)

        return findings
