from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_scaleset_not_empty(Check):
    """
    Ensure that Azure virtual machine scale sets are not empty (i.e., have no VM instances and no load balancer attached).

    This check evaluates whether each VM scale set has zero VM instances and is not associated with any load balancer backend pool.
    - PASS: The scale set has at least one VM instance or is associated with a load balancer backend pool.
    - FAIL: The scale set has no VM instances and is not associated with any load balancer backend pool (i.e., it is empty).
    """

    def execute(self):
        findings = []
        for subscription, scale_sets in vm_client.vm_scale_sets.items():
            for scale_set in scale_sets.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=scale_set
                )
                report.subscription = subscription
                if not scale_set.instance_ids:
                    report.status = "FAIL"
                    report.status_extended = f"Scale set '{scale_set.resource_name}' in subscription '{subscription}' is empty: no VM instances present."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Scale set '{scale_set.resource_name}' in subscription '{subscription}' has {len(scale_set.instance_ids)} VM instances."
                findings.append(report)
        return findings
