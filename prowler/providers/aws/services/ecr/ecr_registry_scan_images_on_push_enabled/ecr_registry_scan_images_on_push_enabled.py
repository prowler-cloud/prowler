from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_registry_scan_images_on_push_enabled(Check):
    def execute(self):
        findings = []
        for registry in ecr_client.registries.values():
            # We want to check the registry if it is in use, hence there are repositories
            if len(registry.repositories) != 0:
                report = Check_Report_AWS(self.metadata())
                report.region = registry.region
                report.resource_id = registry.id
                # A registry cannot have tags
                report.resource_tags = []
                report.status = "FAIL"
                report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning without scan on push enabled."
                if registry.rules:
                    report.status = "PASS"
                    report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scan with scan on push enabled."
                    filters = True
                    for rule in registry.rules:
                        if not rule.scan_filters or "'*'" in str(rule.scan_filters):
                            filters = False
                    if filters:
                        report.status = "FAIL"
                        report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning with scan on push but with repository filters."

                findings.append(report)

        return findings
