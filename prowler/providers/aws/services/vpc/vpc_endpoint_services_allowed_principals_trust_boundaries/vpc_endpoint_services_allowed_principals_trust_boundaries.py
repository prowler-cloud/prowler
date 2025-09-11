from re import compile

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_services_allowed_principals_trust_boundaries(Check):
    def execute(self):
        findings = []
        # Get trusted account_ids from prowler.config.yaml
        trusted_account_ids = vpc_client.audit_config.get("trusted_account_ids", [])
        for service in vpc_client.vpc_endpoint_services:
            report = Check_Report_AWS(metadata=self.metadata(), resource=service)

            if not service.allowed_principals:
                report.status = "PASS"
                report.status_extended = (
                    f"VPC Endpoint Service {service.id} has no allowed principals."
                )
                findings.append(report)
            else:
                for principal in service.allowed_principals:
                    # Account ID can be an ARN or just a 12-digit string
                    pattern = compile(r"^[0-9]{12}$")
                    match = pattern.match(principal)
                    if not match:
                        account_id = (
                            principal.split(":")[4] if principal != "*" else "*"
                        )
                    else:
                        account_id = match.string

                    if (
                        account_id in trusted_account_ids
                        or account_id in vpc_client.audited_account
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Found trusted account {account_id} in VPC Endpoint Service {service.id}."
                    else:
                        report.status = "FAIL"
                        if account_id == "*":
                            report.status_extended = f"Wildcard principal found in VPC Endpoint Service {service.id}."
                        else:
                            report.status_extended = f"Found untrusted account {account_id} in VPC Endpoint Service {service.id}."
                    findings.append(report)

        return findings
