from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_networkacl_unused(Check):
    def execute(self):
        findings = []
        for arn, network_acl in ec2_client.network_acls.items():
            if not network_acl.default:
                report = Check_Report_AWS(self.metadata())
                report.resource_id = network_acl.id
                report.region = network_acl.region
                report.resource_arn = arn
                report.resource_tags = network_acl.tags

                if not network_acl.in_use:
                    report.status = "FAIL"
                    report.status_extended = f"Network ACL {network_acl.name if network_acl.name else network_acl.id} is not associated with any subnet and is not the default network ACL."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Network ACL {network_acl.name if network_acl.name else network_acl.id} is associated with a subnet."

                findings.append(report)

        return findings
