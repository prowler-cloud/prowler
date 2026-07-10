from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_enclave_parent_terminated(Check):
    """Ensure Nitro Enclave parent instances are in the running state.

    Enclaves are destroyed when their parent EC2 instance stops or terminates.
    An enclave-enabled instance that has moved to ``stopping``, ``stopped``,
    ``shutting-down``, or ``terminated`` therefore signals either an
    unexpected outage or a lifecycle change that any consumer relying on
    enclave availability will fail against.

    - PASS: The enclave-enabled instance is in a running (non-terminal) state.
    - FAIL: The instance is stopping/stopped/shutting-down/terminated.
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
            if instance.state in {"stopping", "stopped", "shutting-down", "terminated"}:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is in state "
                    f"'{instance.state}'. Enclaves are destroyed when the parent stops; "
                    f"any expectation of enclave availability is violated."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} is in state "
                    f"'{instance.state}'."
                )
            findings.append(report)
        return findings
