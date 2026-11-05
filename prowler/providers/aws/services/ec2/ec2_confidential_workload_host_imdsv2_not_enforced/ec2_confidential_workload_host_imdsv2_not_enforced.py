from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import (
    HOST_TRUST_MODEL_BOILERPLATE,
    is_enclave_parent,
)


class ec2_confidential_workload_host_imdsv2_not_enforced(Check):
    """Ensure confidential-workload host instances enforce IMDSv2.

    The confidential-workload host (an EC2 instance with
    ``EnclaveOptions.Enabled=true``) inherits and passes its IAM identity to
    every Nitro Enclave it operates. When the host still accepts IMDSv1, SSRF
    and other workload-compromise paths on the host expose the temporary
    credentials the enclave workload depends on. This check assesses the host
    environment; it does not audit the enclave itself.

    - PASS: The host has ``HttpTokens=required`` (IMDSv2 enforced).
    - FAIL: The host still allows IMDSv1 (``HttpTokens=optional``).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the confidential-workload host IMDSv2 enforcement check.

        Iterates confidential-workload hosts (instances with enclaves enabled)
        and reports whether each one enforces IMDSv2 on the metadata service.

        Returns:
            list[Check_Report_AWS]: One report per confidential-workload host.
        """
        findings = []
        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.http_tokens == "required":
                report.status = "PASS"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} enforces "
                    f"IMDSv2. {HOST_TRUST_MODEL_BOILERPLATE}"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Confidential-workload host {instance.id} does not "
                    f"enforce IMDSv2 (HttpTokens={instance.http_tokens}). "
                    f"{HOST_TRUST_MODEL_BOILERPLATE}"
                )
            findings.append(report)
        return findings
