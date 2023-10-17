from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.network_acls import check_network_acl


class ec2_networkacl_allow_ingress_tcp_port_22(Check):
    def execute(self):
        findings = []
        tcp_protocol = "6"
        check_port = 22
        for network_acl in ec2_client.network_acls:
            if ec2_client.audit_info.reduce_noise:
                sg_in_region = False
                for sg in ec2_client.security_groups:
                    if sg.region == network_acl.region and sg.name != "default":
                        sg_in_region = True
                        break
            if not ec2_client.audit_info.reduce_noise or sg_in_region:
                # If some entry allows it, that ACL is not securely configured
                if check_network_acl(network_acl.entries, tcp_protocol, check_port):
                    report = Check_Report_AWS(self.metadata())
                    report.resource_id = network_acl.id
                    report.region = network_acl.region
                    report.resource_arn = network_acl.arn
                    report.resource_tags = network_acl.tags
                    report.status = "FAIL"
                    report.status_extended = f"Network ACL {network_acl.id} has SSH port 22 open to the Internet."
                    findings.append(report)
                else:
                    report = Check_Report_AWS(self.metadata())
                    report.resource_id = network_acl.id
                    report.region = network_acl.region
                    report.resource_arn = network_acl.arn
                    report.resource_tags = network_acl.tags
                    report.status = "PASS"
                    report.status_extended = f"Network ACL {network_acl.id} does not have SSH port 22 open to the Internet."
                    findings.append(report)

        return findings
