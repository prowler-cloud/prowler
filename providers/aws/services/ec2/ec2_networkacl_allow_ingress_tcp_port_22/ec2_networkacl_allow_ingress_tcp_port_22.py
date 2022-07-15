from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_service import ec2_client


class ec2_networkacl_allow_ingress_tcp_port_22(Check):
    def execute(self):
        findings = []
        check_port = 22
        for regional_client in ec2_client.regional_clients:
            region = regional_client.region
            if regional_client.network_acls:
                for network_acl in regional_client.network_acls:
                    public = False
                    report = Check_Report(self.metadata)
                    report.region = region
                    for entry in network_acl.entries:
                        if (
                            entry["CidrBlock"] == "0.0.0.0/0"
                            and entry["RuleAction"] == "allow"
                            and not entry["Egress"]
                            and "PortRange" in entry
                        ):
                            if (
                                entry["PortRange"]["From"] == check_port
                                and entry["PortRange"]["To"] == check_port
                            ):
                                public = True
                                report.status = "FAIL"
                                report.status_extended = f"Network ACL {network_acl.id} has SSH port 22 open to the Internet."
                                report.resource_id = network_acl.id
                    if not public:
                        report.status = "PASS"
                        report.status_extended = f"Network ACL {network_acl.id} has not SSH port 22 open to the Internet."
                        report.resource_id = network_acl.id
                    findings.append(report)
            else:
                report = Check_Report(self.metadata)
                report.status = "PASS"
                report.status_extended = "There are no EC2 network acls."
                report.region = region

                findings.append(report)

        return findings
