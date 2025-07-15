from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_linux_enforce_ssh_authentication(Check):
    """
    Ensure that Azure Linux-based virtual machines are configured to use SSH keys (password authentication is disabled).

    This check evaluates whether disablePasswordAuthentication is set to True for Linux VMs to ensure only SSH key authentication is allowed.
    - PASS: VM has password authentication disabled (SSH key authentication enforced).
    - FAIL: VM has password authentication enabled (password-based SSH allowed).
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription_name, vms in vm_client.virtual_machines.items():
            for vm in vms.values():
                if vm.linux_configuration:
                    report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                    report.subscription = subscription_name

                    if vm.linux_configuration.disable_password_authentication:
                        report.status = "PASS"
                        report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} has password authentication disabled (SSH key authentication enforced)."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} has password authentication enabled (password-based SSH allowed)."
                    findings.append(report)
        return findings
