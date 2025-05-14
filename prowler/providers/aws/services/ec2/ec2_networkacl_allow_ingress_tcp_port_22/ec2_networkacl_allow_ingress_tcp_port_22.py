from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.network_acls import check_network_acl


class ec2_networkacl_allow_ingress_tcp_port_22(Check):
    def execute(self):
        findings = []
        tcp_protocol = "6"
        check_port = 22
        for arn, network_acl in ec2_client.network_acls.items():
            if (
                ec2_client.provider.scan_unused_services
                or network_acl.region in ec2_client.regions_with_sgs
            ):
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=network_acl
                )
                # If some entry allows it, that ACL is not securely configured
                if check_network_acl(network_acl.entries, tcp_protocol, check_port):
                    report.status = "FAIL"
                    report.status_extended = f"Network ACL {network_acl.name if network_acl.name else network_acl.id} has SSH port 22 open to the Internet."
                    findings.append(report)
                else:
                    report.status = "PASS"
                    report.status_extended = f"Network ACL {network_acl.name if network_acl.name else network_acl.id} does not have SSH port 22 open to the Internet."
                    findings.append(report)

        return findings
