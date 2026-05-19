from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.codeartifact.codeartifact_client import (
    codeartifact_client,
)
from prowler.providers.aws.services.codeartifact.codeartifact_service import (
    OriginInformationValues,
    RestrictionValues,
)


class codeartifact_packages_external_public_publishing_disabled(Check):
    def execute(self):
        def evaluate(repository_package):
            repository, package = repository_package
            if package.latest_version.origin.origin_type not in (
                OriginInformationValues.INTERNAL,
                OriginInformationValues.UNKNOWN,
            ):
                return None

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
            return report

        return limited_findings(
            codeartifact_client.iter_packages(),
            evaluate,
            get_resource_scan_limit(
                codeartifact_client.audit_config, "max_codeartifact_packages"
            ),
        )
