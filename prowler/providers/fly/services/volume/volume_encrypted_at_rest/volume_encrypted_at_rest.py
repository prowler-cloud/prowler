from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.volume.volume_client import volume_client


class volume_encrypted_at_rest(Check):
    """Check if a Fly.io volume is encrypted at rest.

    Fly.io volumes carry the persistent state of an app, including databases and
    user-uploaded files, and can be created unencrypted.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io volume encryption check.

        Returns:
            List[CheckReportFly]: A report per in-scope volume.
        """
        findings = []

        for volume in volume_client.volumes.values():
            report = CheckReportFly(metadata=self.metadata(), resource=volume)

            if volume.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) in app {volume.app_name} is "
                    f"encrypted at rest."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Volume {volume.name} ({volume.id}) in app {volume.app_name} is "
                    f"not encrypted at rest."
                )

            findings.append(report)

        return findings
