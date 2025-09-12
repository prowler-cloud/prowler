from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_ensure_using_approved_images(Check):
    """
    Ensure that Azure VMs are using an approved (custom) machine image.

    This check evaluates whether Azure Virtual Machines are launched from an approved (custom) machine image by checking the image reference ID format.

    - PASS: The Azure VM is using an approved custom machine image.
    - FAIL: The Azure VM is not using an approved custom machine image.
    """

    def execute(self):
        findings = []
        for subscription_name, vms in vm_client.virtual_machines.items():
            for vm in vms.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription_name
                image_id = getattr(vm, "image_reference", None)
                if (
                    image_id
                    and image_id.startswith("/subscriptions/")
                    and "/providers/Microsoft.Compute/images/" in image_id
                ):
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} is using an approved machine image: {image_id.split('/')[-1]}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} is not using an approved machine image."
                findings.append(report)
        return findings
