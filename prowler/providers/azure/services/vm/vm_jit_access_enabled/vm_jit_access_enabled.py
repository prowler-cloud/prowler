from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.defender.defender_client import defender_client
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_jit_access_enabled(Check):
    """
    Ensure that Microsoft Azure virtual machines are configured to use Just-in-Time (JIT) access.

    This check evaluates whether JIT access is enabled for each VM to reduce the attack surface.
    - PASS: VM has JIT access enabled.
    - FAIL: VM does not have JIT access enabled.
    """

    def execute(self):
        findings = []
        jit_enabled_vms = set()
        for subscription_name, vms in vm_client.virtual_machines.items():
            for jit_policy in defender_client.jit_policies[subscription_name].values():
                jit_enabled_vms.update(jit_policy.vm_ids)
            for vm in vms.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription_name
                if vm.resource_id.lower() in {
                    vm_id.lower() for vm_id in jit_enabled_vms
                }:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} has JIT (Just-in-Time) access enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} does not have JIT (Just-in-Time) access enabled."
                findings.append(report)
        return findings
