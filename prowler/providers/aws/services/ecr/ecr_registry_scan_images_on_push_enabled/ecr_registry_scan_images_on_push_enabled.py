from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client

# The two frequencies that scan an image without anyone asking. MANUAL is the third value
# GetRegistryScanningConfiguration can return, and it is the default a BASIC registry gets when
# scan on push is not specified, so it is the state this check exists to catch.
AUTOMATED_SCAN_FREQUENCIES = {"SCAN_ON_PUSH", "CONTINUOUS_SCAN"}


class ecr_registry_scan_images_on_push_enabled(Check):
    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check against every ECR registry that holds repositories.

        Returns:
            A list of reports, one per in-use registry, PASS when its rules cover all
            repositories with a frequency in AUTOMATED_SCAN_FREQUENCIES.
        """
        findings = []
        for registry in ecr_client.registries.values():
            # We want to check the registry if it is in use, hence there are repositories
            if len(registry.repositories) != 0:
                report = Check_Report_AWS(metadata=self.metadata(), resource=registry)
                report.status = "FAIL"
                report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning without automated scanning enabled."
                if registry.rules:
                    # Read the frequency rather than inferring it from the presence of a rule. A rule
                    # always carries one -- scanFrequency is required on the shape -- and a MANUAL
                    # rule is a registry where nothing is scanned until someone runs a scan by hand.
                    frequencies = {
                        rule.scan_frequency
                        for rule in registry.rules
                        if rule.scan_frequency in AUTOMATED_SCAN_FREQUENCIES
                    }
                    if frequencies:
                        report.status = "PASS"
                        report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning with {self._describe(frequencies)} for all repositories."
                        filters = True
                        for rule in registry.rules:
                            if not rule.scan_filters or "'*'" in str(rule.scan_filters):
                                filters = False
                        if filters:
                            report.status = "FAIL"
                            report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning with {self._describe(frequencies)} but with repository filters."
                    else:
                        report.status_extended = f"ECR registry {registry.id} has {registry.scan_type} scanning set to manual only, so images are not scanned when they are pushed."

                findings.append(report)

        return findings

    @staticmethod
    def _describe(frequencies: set) -> str:
        """Name automated scan frequencies in a fixed order.

        Args:
            frequencies: The registry's configured frequencies, already narrowed to
                AUTOMATED_SCAN_FREQUENCIES.

        Returns:
            The frequencies in a fixed order, so the message does not vary between runs for
            the same registry.
        """
        wording = {
            "SCAN_ON_PUSH": "scan on push",
            "CONTINUOUS_SCAN": "continuous scanning",
        }
        return " and ".join(
            wording[f] for f in ("SCAN_ON_PUSH", "CONTINUOUS_SCAN") if f in frequencies
        )
