from re import compile

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
            if endpoint.policy_document:
                for statement in endpoint.policy_document["Statement"]:
                    if "*" == statement["Principal"]:
                        report = Check_Report_AWS(self.metadata())
                        report.region = endpoint.region
                        report.status = "FAIL"
                        report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."
                        report.resource_id = endpoint.id
                        report.resource_arn = endpoint.arn
                        report.resource_tags = endpoint.tags
                        findings.append(report)
                        break

                    else:
                        if type(statement["Principal"]["AWS"]) == str:
                            principals = [statement["Principal"]["AWS"]]
                        else:
                            principals = statement["Principal"]["AWS"]
                        for principal_arn in principals:
                            report = Check_Report_AWS(self.metadata())
                            report.region = endpoint.region
                            if principal_arn == "*":
                                report.status = "FAIL"
                                report.status_extended = f"VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id} has full access."
                                report.resource_id = endpoint.id
                                report.resource_arn = endpoint.arn
                                report.resource_tags = endpoint.tags
                            else:
                                # Account ID can be an ARN or just a 12-digit string
                                pattern = compile(r"^[0-9]{12}$")
                                match = pattern.match(principal_arn)
                                if not match:
                                    account_id = principal_arn.split(":")[4]
                                else:
                                    account_id = match.string
                                if (
                                    account_id in trusted_account_ids
                                    or account_id in vpc_client.audited_account
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"Found trusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."
                                    report.resource_id = endpoint.id
                                    report.resource_arn = endpoint.arn
                                    report.resource_tags = endpoint.tags
                                else:
                                    report.status = "FAIL"
                                    report.status_extended = f"Found untrusted account {account_id} in VPC Endpoint {endpoint.id} in VPC {endpoint.vpc_id}."
                                    report.resource_id = endpoint.id
                                    report.resource_arn = endpoint.arn
                                    report.resource_tags = endpoint.tags
                            findings.append(report)

        return findings
