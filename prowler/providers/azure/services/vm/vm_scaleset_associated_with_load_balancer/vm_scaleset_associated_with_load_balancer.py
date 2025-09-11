from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_scaleset_associated_with_load_balancer(Check):
    """
    Ensure that Azure virtual machine scale sets are associated with a load balancer backend pool.

    This check evaluates whether each VM scale set is associated with at least one load balancer backend pool.
    - PASS: The scale set is associated with a load balancer backend pool.
    - FAIL: The scale set is not associated with any load balancer backend pool.
    """

    def execute(self):
        findings = []
        for subscription, scale_sets in vm_client.vm_scale_sets.items():
            for scale_set in scale_sets.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=scale_set
                )
                report.subscription = subscription
                report.resource_id = scale_set.resource_id
                report.resource_name = scale_set.resource_name
                report.location = scale_set.location
                if scale_set.load_balancer_backend_pools:
                    report.status = "PASS"
                    backend_pool_names = [
                        pool.split("/")[-1]
                        for pool in scale_set.load_balancer_backend_pools
                    ]
                    report.status_extended = f"Scale set '{scale_set.resource_name}' in subscription '{subscription}' is associated with load balancer backend pool(s): {', '.join(backend_pool_names)}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Scale set '{scale_set.resource_name}' in subscription '{subscription}' is not associated with any load balancer backend pool."
                findings.append(report)
        return findings
