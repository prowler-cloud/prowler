from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)
from prowler.providers.aws.services.servicecatalog.servicecatalog_client import (
    servicecatalog_client,
)


class servicecatalog_portfolio_shared_within_organization_only(Check):
    def execute(self):
        findings = []
        if (
            organizations_client.organization
            and organizations_client.organization.status == "ACTIVE"
        ):
            for portfolio in servicecatalog_client.portfolios.values():
                if portfolio.shares is not None:
                    report = Check_Report_AWS(self.metadata())
                    report.region = portfolio.region
                    report.resource_id = portfolio.id
                    report.resource_arn = portfolio.arn
                    report.resource_tags = portfolio.tags
                    report.status = "PASS"
                    report.status_extended = f"ServiceCatalog Portfolio {portfolio.name} is shared within your AWS Organization."
                    for portfolio_share in portfolio.shares:
                        if portfolio_share.type == "ACCOUNT":
                            report.status = "FAIL"
                            report.status_extended = f"ServiceCatalog Portfolio {portfolio.name} is shared with an account."
                            break

                    findings.append(report)

        return findings
