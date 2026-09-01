from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.machine.machine_client import machine_client


class machine_image_pinned_to_digest(Check):
    """Check if a Fly.io machine runs an image pinned to an immutable digest.

    A machine whose configured image is a mutable tag can silently change on the
    next restart, so the running artifact cannot be tied back to a reviewed
    build.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine image provenance check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)

            if "@sha256:" in machine.image:
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} runs the "
                    f"digest-pinned image {machine.image}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} runs the "
                    f"mutable image reference {machine.image or 'unknown'}, which "
                    f"cannot be tied to an immutable build artifact."
                )

            findings.append(report)

        return findings
