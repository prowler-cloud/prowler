from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "PASS"
            report.status_extended = (
                f"Opensearch domain {domain.name} does not allow anonymous access"
            )
            if domain.access_policy:
                for statement in domain.access_policy["Statement"]:
                    # look for open policies
                    if (
                        statement["Effect"] == "Allow"
                        and (
                            "AWS" in statement["Principal"]
                            and "*" in statement["Principal"]["AWS"]
                        )
                        or (statement["Principal"] == "*")
                    ):
                        if "Condition" not in statement:
                            report.status = "FAIL"
                            report.status_extended = f"Opensearch domain {domain.name} policy allows access (Principal: '*')"
                            break
                        else:
                            if (
                                "IpAddress" in statement["Condition"]
                                and "aws:SourceIp"
                                in statement["Condition"]["IpAddress"]
                            ):
                                for ip in statement["Condition"]["IpAddress"][
                                    "aws:SourceIp"
                                ]:
                                    if ip == "*":
                                        report.status = "FAIL"
                                        report.status_extended = f"Opensearch domain {domain.name} policy allows access (Principal: '*') and network *"
                                        break
                                    elif ip == "0.0.0.0/0":
                                        report.status = "FAIL"
                                        report.status_extended = f"Opensearch domain {domain.name} policy allows access (Principal: '*') and network 0.0.0.0/0"
                                        break

            findings.append(report)

        return findings
