from prowler.lib.check.models import Check, Check_Report_GCP, Severity
from prowler.lib.threats import (
    describe_matches,
    load_signatures,
    match_image,
    to_match,
    worst_severity,
)
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_emerging_threat_image(Check):
    """VM instances do not boot from an image that a known emerging threat affects.

    The image is the boot disk's source image. Its project verifies provenance
    when a signature lists it (for example ``debian-cloud``); an imported image
    matches on its name.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        signatures = load_signatures(compute_client.audit_config)
        if not signatures:
            return findings

        for instance in compute_client.instances:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance,
                location=instance.zone,
            )
            if instance.boot_image_lookup_failed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate VM Instance {instance.name} against known emerging "
                    "threats: its boot disk could not be retrieved. Verify that "
                    "compute.disks.list and compute.regionDisks.list are granted to "
                    "the scanning identity."
                )
                findings.append(report)
                continue
            if not instance.boot_image:
                report.status = "PASS"
                report.status_extended = (
                    f"VM Instance {instance.name} does not report the image its boot "
                    "disk was created from, so no known emerging threat could be matched."
                )
                findings.append(report)
                continue

            hits = match_image(
                signatures,
                "gcp",
                [instance.boot_image],
                instance.boot_image_project,
            )
            if not hits:
                report.status = "PASS"
                report.status_extended = (
                    f"VM Instance {instance.name} boots from image "
                    f"{instance.boot_image}, which no known emerging threat affects."
                )
                findings.append(report)
                continue

            matches = [
                to_match(
                    signature,
                    matched_name,
                    provenance,
                    # Firewall rules are evaluated by their own checks; a
                    # public IP is what this instance proves on its own.
                    public_route=(
                        instance.public_ip or instance.public_ipv6
                        if signature.exposure
                        else None
                    ),
                )
                for signature, matched_name, provenance in hits
            ]
            report.status = "FAIL"
            report.check_metadata.Severity = Severity(worst_severity(matches))
            report.raw = {
                "threats": [match.model_dump(mode="json") for match in matches]
            }
            report.status_extended = (
                f"VM Instance {instance.name} boots from image {instance.boot_image}, "
                f"which ships a build affected by {describe_matches(matches)}. "
                "Prowler sees the image the boot disk was created from, not packages "
                "updated since: mute this finding if the host was patched in place."
            )
            findings.append(report)
        return findings
