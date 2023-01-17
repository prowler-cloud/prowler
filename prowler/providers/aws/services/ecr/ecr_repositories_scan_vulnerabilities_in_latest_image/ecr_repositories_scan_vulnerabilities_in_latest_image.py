from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_scan_vulnerabilities_in_latest_image(Check):
    def execute(self):
        findings = []
        for repository in ecr_client.repositories:
            for image in repository.images_details:
                report = Check_Report_AWS(self.metadata())
                report.region = repository.region
                report.resource_id = repository.name
                report.resource_arn = repository.arn
                report.status = "PASS"
                report.status_extended = f"ECR repository {repository.name} has imageTag {image.latest_tag} scanned without findings"
                if not image.scan_findings_status:
                    report.status = "FAIL"
                    report.status_extended = f"ECR repository {repository.name} has imageTag {image.latest_tag} without a scan"
                elif image.scan_findings_status == "FAILED":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ECR repository {repository.name} with scan status FAILED"
                    )
                elif image.scan_findings_status != "FAILED":
                    if image.scan_findings_severity_count and (
                        image.scan_findings_severity_count.critical
                        or image.scan_findings_severity_count.high
                        or image.scan_findings_severity_count.medium
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"ECR repository {repository.name} has imageTag {image.latest_tag} scanned with findings: CRITICAL->{image.scan_findings_severity_count.critical}, HIGH->{image.scan_findings_severity_count.high}, MEDIUM->{image.scan_findings_severity_count.medium} "

                findings.append(report)

        return findings
