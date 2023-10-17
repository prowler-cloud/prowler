from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_findings_exist(Check):
    def execute(self):
        findings = []
        for inspector in inspector2_client.inspectors:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = inspector2_client.audited_account
            report.resource_arn = inspector2_client.audited_account_arn
            report.region = inspector.region
            if inspector.status == "ENABLED":
                active_findings = 0
                report.status = "PASS"
                report.status_extended = "Inspector2 is enabled with no findings."
                for finding in inspector.findings:
                    if finding.status == "ACTIVE":
                        active_findings += 1
                if len(inspector.findings) > 0:
                    report.status_extended = (
                        "Inspector2 is enabled with no active findings."
                    )
                    if active_findings > 0:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"There are {active_findings} ACTIVE Inspector2 findings."
                        )
                findings.append(report)
            else:
                funtions_in_region = False
                ec2_in_region = False
                for function in awslambda_client.functions.values():
                    if function.region == inspector.region:
                        funtions_in_region = True
                for instance in ec2_client.instances:
                    if instance == inspector.region:
                        ec2_in_region = True
                if not inspector2_client.audit_info.ignore_unused_services or (
                    funtions_in_region
                    or ecr_client.registries[inspector.region].repositories
                    or ec2_in_region
                ):
                    report.status = "FAIL"
                    report.status_extended = "Inspector2 is not enabled."
                    findings.append(report)

        return findings
