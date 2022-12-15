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
        findings = []
        for repository in codeartifact_client.repositories.values():
            for package in repository.packages:
                report = Check_Report_AWS(self.metadata())
                report.region = repository.region
                report.resource_id = package.name

                if package.latest_version.origin.origin_type in (
                    OriginInformationValues.INTERNAL,
                    OriginInformationValues.UNKNOWN,
                ):
                    if (
                        package.origin_configuration.restrictions.upstream
                        == RestrictionValues.ALLOW
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Internal package {package.namespace} {package.name} is vulnerable to dependency confusion in repository {repository.arn}"
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Internal package {package.namespace} {package.name} is not vulnerable to dependency confusion in repository {repository.arn}"

                findings.append(report)

        return findings
