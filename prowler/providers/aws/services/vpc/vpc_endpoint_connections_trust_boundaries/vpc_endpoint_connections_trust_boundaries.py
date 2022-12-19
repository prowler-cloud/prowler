from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_endpoint_connections_trust_boundaries(Check):
    def execute(self):
        findings = []
        # Get trusted account_ids from prowler.config.yaml
        trusted_account_ids = get_config_var("trusted_account_ids")
        for endpoint in vpc_client.vpc_endpoints:
            # Check VPC endpoint policy
            for statement in endpoint.policy_document["Statement"]:
                if "*" == statement["Principal"]:
                    report = Check_Report_AWS(self.metadata())
                    report.region = endpoint.region
                    report.status = "FAIL"
                    report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."
                    report.resource_id = endpoint.id
                    findings.append(report)
                    break

                else:
                    if type(statement["Principal"]["AWS"]) == str:
                        principals = [statement["Principal"]["AWS"]]
                    else:
                        principals = statement["Principal"]["AWS"]
                    for principal_arn in principals:
                        account_id = principal_arn.split(":")[4]
                        report = Check_Report_AWS(self.metadata())
                        report.region = endpoint.region
                        if (
                            account_id in trusted_account_ids
                            or account_id in vpc_client.audited_account
                        ):
                            report.status = "PASS"
                            report.status_extended = f"Found trusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."
                            report.resource_id = endpoint.id
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"Found untrusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."
                            report.resource_id = endpoint.id
                        findings.append(report)

        return findings
