from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.vm.vm_client import vm_client

class vm_context_insecure(Check):
    def execute(self):
        findings = []
        logger.info("Checking for OpenNebula VMs with insecure secrets in CONTEXT...")

        sensitive_keys = ["PASSWORD", "SSH_PRIVATE_KEY", "TOKEN", "DB_PASSWORD", "API_KEY", "SECRET_KEY"]

        for vm in vm_client.vms:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=vm.name,
            )
            insecure_secrets = []

            for key in sensitive_keys:
                if key in vm.context:
                    value = vm.context[key]
                    if value and not value.startswith("$"):
                        insecure_secrets.append(key)

            if insecure_secrets:
                report.status = "FAIL"
                report.status_extended = (
                    f"VM {vm.name} contains insecure secrets in CONTEXT: {', '.join(insecure_secrets)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"VM {vm.name} has no insecure secrets detected in CONTEXT."
                )

            findings.append(report)

        return findings
