from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import is_enclave_parent


class ec2_enclave_parent_imdsv2_not_enforced(Check):
    """Ensure Nitro Enclave parent instances enforce IMDSv2.

    Nitro Enclaves inherit the parent EC2 instance's IAM identity through the
    instance metadata service. When the parent still accepts IMDSv1, SSRF and
    other workload-compromise paths on the parent expose the temporary
    credentials the enclave is meant to gate.

    - PASS: The parent instance has ``HttpTokens=required`` (IMDSv2 enforced).
    - FAIL: The parent instance still allows IMDSv1 (``HttpTokens=optional``).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave IMDSv2 enforcement check.

        Iterates over enclave-parent instances and reports whether each one
        enforces IMDSv2 on the instance metadata service.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.http_tokens == "required":
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} enforces IMDSv2."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} does not enforce "
                    f"IMDSv2 (HttpTokens={instance.http_tokens})."
                )
            findings.append(report)
        return findings
