from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_is_enabled(Check):
    def execute(self):
        findings = []
        for inspector in inspector2_client.inspectors:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = inspector.id
            report.resource_arn = inspector.arn
            report.region = inspector.region
            if inspector.status == "ENABLED":
                report.status = "PASS"
                report.status_extended = "Inspector2 is enabled for EC2 instances, ECR container images, Lambda functions and code."
                funtions_in_region = False
                ec2_in_region = False
                for function in awslambda_client.functions.values():
                    if function.region == inspector.region:
                        funtions_in_region = True
                for instance in ec2_client.instances:
                    if instance == inspector.region:
                        ec2_in_region = True
                failed_services = []

                if inspector.ec2_status != "ENABLED" and (
                    inspector2_client.provider.scan_unused_services or ec2_in_region
                ):
                    failed_services.append("EC2")
                if inspector.ecr_status != "ENABLED" and (
                    inspector2_client.provider.scan_unused_services
                    or ecr_client.registries[inspector.region].repositories
                ):
                    failed_services.append("ECR")
                if inspector.lambda_status != "ENABLED" and (
                    inspector2_client.provider.scan_unused_services
                    or funtions_in_region
                ):
                    failed_services.append("Lambda")
                if inspector.lambda_code_status != "ENABLED" and (
                    inspector2_client.provider.scan_unused_services
                    or funtions_in_region
                ):
                    failed_services.append("Lambda Code")

                if failed_services:
                    report.status = "FAIL"
                    report.status_extended = f"Inspector2 is not enabled for the following services: {', '.join(failed_services)}."
                findings.append(report)
            else:
                report.status = "FAIL"
                report.status_extended = "Inspector2 is not enabled in this account."
                findings.append(report)

        return findings
