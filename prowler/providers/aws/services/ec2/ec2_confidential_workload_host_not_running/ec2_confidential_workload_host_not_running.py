from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    HOST_TRUST_MODEL_BOILERPLATE,
)

_TERMINAL_STATES = frozenset({"stopped", "shutting-down", "terminated"})
_TRANSIENT_STATES = frozenset({"pending", "stopping"})


class ec2_confidential_workload_host_not_running(Check):
    """Ensure Nitro Enclave parent instances are in the running state.

    Enclaves are destroyed when their parent EC2 instance stops or terminates.
    An enclave-enabled instance that has moved to ``stopped``,
    ``shutting-down``, or ``terminated`` therefore signals either an
    unexpected outage or a lifecycle change that any consumer relying on
    enclave availability will fail against. Transient lifecycle states
    (``pending``, ``stopping``) are reported as PASS with a note.

    - PASS: The enclave-enabled instance is running or in a transient state.
    - FAIL: The instance is stopped/shutting-down/terminated.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave parent state check.

        Iterates over every enclave-enabled EC2 instance (including terminal
        states, unlike the shared ``is_enclave_parent`` helper) and reports
        whether the instance is still in a running lifecycle state.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        for instance in ec2_client.instances:
            if not instance.enclaves_enabled:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.state in _TERMINAL_STATES:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is in state "
                    f"'{instance.state}'. Enclaves are destroyed when the parent "
                    f"stops; any expectation of enclave availability is violated. "
                    f"{HOST_TRUST_MODEL_BOILERPLATE}"
                )
            elif instance.state in _TRANSIENT_STATES:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is in transient "
                    f"state '{instance.state}'; re-evaluate after the lifecycle "
                    f"transition settles. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is in state "
                    f"'{instance.state}'. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            findings.append(report)
        return findings
