from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_registry_enhanced_scanning_enabled(Check):
    """Verify that in-use ECR registries have enhanced scanning enabled.

    Enhanced scanning (Amazon Inspector) covers operating system and programming
    language packages with continuous rescanning as new CVEs are published, while
    basic scanning only covers operating system packages at push time against a
    static CVE list. Only registries holding at least one repository are checked.
    - PASS: the registry scan type is ENHANCED.
    - FAIL: the registry is on another scan type.
    - MANUAL: the registry scanning configuration could not be retrieved, so the
      scan type is unknown.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for registry in ecr_client.registries.values():
            # We want to check the registry if it is in use, hence there are repositories
            if len(registry.repositories) != 0:
                report = Check_Report_AWS(metadata=self.metadata(), resource=registry)
                if registry.scan_type is None:
                    report.status = "MANUAL"
                    report.status_extended = f"ECR registry {registry.id} scanning configuration could not be retrieved, check manually if enhanced scanning is enabled."
                elif registry.scan_type == "ENHANCED":
                    report.status = "PASS"
                    report.status_extended = (
                        f"ECR registry {registry.id} has enhanced scanning enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning enabled instead of enhanced scanning."

                findings.append(report)

        return findings
