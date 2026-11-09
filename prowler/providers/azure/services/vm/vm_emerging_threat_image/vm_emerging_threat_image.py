from prowler.lib.check.models import Check, Check_Report_Azure, Severity
from prowler.lib.threats import (
    describe_matches,
    load_signatures,
    match_image,
    to_match,
    worst_severity,
)
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_emerging_threat_image(Check):
    """Azure VMs are not created from an image that a known emerging threat affects.

    The image is identified by every name Azure reports for it: gallery image
    definition, custom image, or marketplace offer and SKU. Marketplace
    publishers verify provenance; gallery and custom images match on name.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        signatures = load_signatures(vm_client.audit_config)
        if not signatures:
            return findings

        for subscription_id, vms in vm_client.virtual_machines.items():
            subscription_name = vm_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for vm in vms.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription_id
                where = f"in subscription {subscription_name} ({subscription_id})"
                if vm.image is None or not vm.image.names:
                    report.status = "PASS"
                    report.status_extended = (
                        f"VM {vm.resource_name} {where} does not report the image it was "
                        "created from, so no known emerging threat could be matched."
                    )
                    findings.append(report)
                    continue

                hits = match_image(
                    signatures, "azure", vm.image.names, vm.image.publisher
                )
                if not hits:
                    report.status = "PASS"
                    report.status_extended = (
                        f"VM {vm.resource_name} {where} was created from an image no "
                        "known emerging threat affects."
                    )
                    findings.append(report)
                    continue

                password_disabled = bool(
                    vm.linux_configuration
                    and vm.linux_configuration.disable_password_authentication
                )
                matches = [
                    to_match(
                        signature,
                        matched_name,
                        provenance,
                        mitigations_observed=(
                            ["password_authentication_disabled"]
                            if password_disabled
                            and "password_authentication_disabled"
                            in signature.mitigations
                            else []
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
                    f"VM {vm.resource_name} {where} was created from an image that "
                    f"ships a build affected by {describe_matches(matches)}. Prowler "
                    "sees the image the VM was created from, not packages updated "
                    "since: mute this finding if the host was patched in place."
                )
                findings.append(report)
        return findings
