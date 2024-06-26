from re import compile

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_services_allowed_principals_trust_boundaries(Check):
    def execute(self):
        findings = []
        # Get trusted account_ids from prowler.config.yaml
        trusted_account_ids = vpc_client.audit_config.get("trusted_account_ids", [])
        for service in vpc_client.vpc_endpoint_services:
            if not service.allowed_principals:
                report = Check_Report_AWS(self.metadata())
                report.region = service.region
                report.status = "PASS"
                report.status_extended = (
                    f"VPC Endpoint Service {service.id} has no allowed principals."
                )
                report.resource_id = service.id
                report.resource_arn = service.arn
                report.resource_tags = service.tags
                findings.append(report)
            else:
                for principal in service.allowed_principals:
                    # Account ID can be an ARN or just a 12-digit string
                    pattern = compile(r"^[0-9]{12}$")
                    match = pattern.match(principal)
                    if not match:
                        account_id = principal.split(":")[4]
                    else:
                        account_id = match.string

                    report = Check_Report_AWS(self.metadata())
                    report.region = service.region
                    if (
                        account_id in trusted_account_ids
                        or account_id in vpc_client.audited_account
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Found trusted account {account_id} in VPC Endpoint Service {service.id}."
                        report.resource_id = service.id
                        report.resource_arn = service.arn
                        report.resource_tags = service.tags
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Found untrusted account {account_id} in VPC Endpoint Service {service.id}."
                        report.resource_id = service.id
                        report.resource_arn = service.arn
                        report.resource_tags = service.tags
                    findings.append(report)

        return findings
