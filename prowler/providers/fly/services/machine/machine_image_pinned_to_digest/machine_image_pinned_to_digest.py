from typing import List

from prowler.lib.check.models import Check, CheckReportFly
from prowler.providers.fly.services.machine.machine_client import machine_client

DIGEST_MARKER = "@sha256:"


class machine_image_pinned_to_digest(Check):
    """Check if a Fly.io machine runs an image pinned to an immutable digest.

    A machine whose configured image is a mutable tag can silently change on the
    next update, so the running artifact cannot be tied back to a reviewed
    build. Pinning is judged on the configured reference (``config.image``).
    The ``image_ref.digest`` returned by the Machines API is the digest of the
    image Fly.io pulled and is populated for mutable tags too, so it is only
    reported to help pin the image, never taken as evidence of pinning.
    """

    def execute(self) -> List[CheckReportFly]:
        """Execute the Fly.io machine image provenance check.

        Returns:
            List[CheckReportFly]: A report per in-scope machine.
        """
        findings = []

        for machine in machine_client.machines.values():
            report = CheckReportFly(metadata=self.metadata(), resource=machine)
            image = (machine.image or "").strip()
            resolved = (
                f" Fly.io reports the running image digest {machine.image_digest}, "
                f"which can be used to pin the image."
                if machine.image_digest
                else ""
            )

            if not image:
                # The configured reference is unknown: never claim pinning from a gap.
                report.status = "MANUAL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} has no image "
                    f"reference in its configuration, so image pinning could not be "
                    f"determined; verify it manually with 'fly machine status "
                    f"{machine.id} -a {machine.app_name}'.{resolved}"
                )
            elif DIGEST_MARKER in image.lower():
                report.status = "PASS"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} runs the "
                    f"digest-pinned image {image}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Machine {machine.name} in app {machine.app_name} runs the "
                    f"mutable image reference {image}, which cannot be tied to an "
                    f"immutable build artifact.{resolved}"
                )

            findings.append(report)

        return findings
