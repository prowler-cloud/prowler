from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_desired_sku_size(Check):
    """
    Ensure that Azure virtual machines are using SKU sizes that are approved by your organization.

    This check evaluates whether each virtual machine's SKU size is included in the organization's approved list of VM sizes.
    The approved SKU sizes are configured in the Prowler configuration file under azure.desired_vm_sku_sizes.
    - PASS: The VM is using a SKU size that is approved by the organization.
    - FAIL: The VM is using a SKU size that is not approved by the organization.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """
        Execute the check to verify that virtual machines are using desired SKU sizes.

        Returns:
            A list of check reports for each virtual machine
        """

        findings = []

        # Get the desired SKU sizes from configuration
        DESIRED_SKU_SIZES = vm_client.audit_config.get(
            "desired_vm_sku_sizes",
            [
                "Standard_A8_v2",
                "Standard_DS3_v2",
                "Standard_D4s_v3",
            ],
        )

        for subscription_name, vms in vm_client.virtual_machines.items():
            for vm in vms.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription_name

                if vm.vm_size in DESIRED_SKU_SIZES:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} is using desired SKU size {vm.vm_size} in subscription {subscription_name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} is using {vm.vm_size} which is not a desired SKU size in subscription {subscription_name}."

                findings.append(report)

        return findings
