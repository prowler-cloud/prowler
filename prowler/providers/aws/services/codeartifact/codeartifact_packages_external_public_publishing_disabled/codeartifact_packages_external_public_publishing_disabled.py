from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.codeartifact.codeartifact_client import (
    codeartifact_client,
)
from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    OriginInformationValues,
    RestrictionValues,
)


class codeartifact_packages_external_public_publishing_disabled(Check):
    def execute(self):
        reports = []
        for repository, package in codeartifact_client.iter_packages():
            if package.latest_version.origin.origin_type not in (
                OriginInformationValues.INTERNAL,
                OriginInformationValues.UNKNOWN,
            ):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
            report.resource_id = f"{repository.domain_name}/{package.name}"
            report.resource_arn = f"{repository.arn}/{package.namespace + ':' if package.namespace else ''}{package.name}"

            if (
                package.origin_configuration.restrictions.upstream
                == RestrictionValues.ALLOW
            ):
                report.status = "FAIL"
                report.status_extended = f"Internal package {package.name} is vulnerable to dependency confusion in repository {repository.domain_name}."
            else:
                report.status = "PASS"
                report.status_extended = f"Internal package {package.name} is not vulnerable to dependency confusion in repository {repository.domain_name}."
            reports.append(report)
        return reports
