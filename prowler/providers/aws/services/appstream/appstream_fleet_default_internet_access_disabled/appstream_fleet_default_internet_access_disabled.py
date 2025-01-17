from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appstream.appstream_client import appstream_client


# Check if there are AppStream Fleets with the default internet access enabled
class appstream_fleet_default_internet_access_disabled(Check):
    """Check if there are AppStream Fleets with the default internet access enabled"""

    def execute(self):
        """Execute the appstream_fleet_default_internet_access_disabled check"""
        findings = []
        for fleet in appstream_client.fleets:
            report = Check_Report_AWS(metadata=self.metadata(), resource=fleet)

            if fleet.enable_default_internet_access:
                report.status = "FAIL"
                report.status_extended = (
                    f"Fleet {fleet.name} has default internet access enabled."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Fleet {fleet.name} has default internet access disabled."
                )

            findings.append(report)

        return findings
