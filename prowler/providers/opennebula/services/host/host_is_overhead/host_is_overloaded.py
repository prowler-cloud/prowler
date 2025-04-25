from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.host.host_client import host_client

class host_is_overloaded(Check):
    def execute(self):
        findings = []
        logger.info("Checking for OpenNebula hosts with resource overuse or imbalance...")
        for host in host_client.hosts:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=host.name,
            )
            overloaded = False
            details = []

            if host.total_cpu and host.used_cpu is not None:
                cpu_ratio = host.used_cpu / host.total_cpu
                if cpu_ratio > 0.9:
                    overloaded = True
                    details.append(f"CPU usage is {cpu_ratio:.1%}")

            if host.total_mem and host.used_mem is not None:
                mem_ratio = host.used_mem / host.total_mem
                if mem_ratio > 0.9:
                    overloaded = True
                    details.append(f"Memory usage is {mem_ratio:.1%}")

            if overloaded:
                report.status = "FAIL"
                report.status_extended = f"Host {host.name} is overloaded: {', '.join(details)}."
            else:
                report.status = "PASS"
                report.status_extended = f"Host {host.name} resource usage is within safe limits."

            findings.append(report)
        return findings
