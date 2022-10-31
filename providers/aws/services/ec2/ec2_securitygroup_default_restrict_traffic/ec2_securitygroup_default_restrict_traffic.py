from lib.check.models import Check, Check_Report
from providers.aws.services.ec2.ec2_client import ec2_client
from providers.aws.services.ec2.lib.security_groups import check_security_group


class ec2_securitygroup_default_restrict_traffic(Check):
    def execute(self):
        findings = []
        for security_group in ec2_client.security_groups:
            public = False
            report = Check_Report(self.metadata)
            report.region = security_group.region
            # Find default security group
            if security_group.name == "default":
                for ingress_rule in security_group.ingress_rules:
                    public = check_security_group(ingress_rule, "-1")
                if public:
                    report.status = "FAIL"
                    report.status_extended = f"Default Security Group ({security_group.id}) is open to 0.0.0.0."
                    report.resource_id = security_group.id
                else:
                    report.status = "PASS"
                    report.status_extended = f"Default Security Group ({security_group.id}) is not open to 0.0.0.0."
                    report.resource_id = security_group.id
                findings.append(report)

        return findings
