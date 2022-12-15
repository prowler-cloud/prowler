from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ssm.ssm_client import ssm_client
from prowler.providers.aws.services.ssm.ssm_service import ResourceStatus


class ssm_managed_compliant_patching(Check):
    def execute(self):
        findings = []
        for resource in ssm_client.compliance_resources.values():
            report = Check_Report_AWS(self.metadata())
            report.region = resource.region
            report.resource_arn = f"arn:aws:ec2:{resource.region}:{ssm_client.audited_account}:instance/{resource.id}"
            report.resource_id = resource.id

            if resource.status == ResourceStatus.COMPLIANT:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 managed instance {resource.id} is compliant"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 managed instance {resource.id} is non-compliant"
                )

            findings.append(report)

        return findings
