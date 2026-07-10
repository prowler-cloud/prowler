from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.enclave import is_enclave_parent


class ec2_enclave_parent_hibernation_enabled(Check):
    """Ensure Nitro Enclave parent instances do not have hibernation enabled.

    Hibernation serializes RAM (which may include enclave memory contents) to
    EBS. AWS currently blocks combining ``EnclaveOptions.Enabled=true`` with
    ``HibernationOptions.Configured=true`` at the RunInstances API level with
    ``InvalidParameterCombination``, so any instance found in this state
    indicates a platform anomaly or an undocumented launch path.

    - PASS: The enclave parent does not have hibernation configured.
    - FAIL: The enclave parent has hibernation configured (anomalous state).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Nitro Enclave hibernation-disabled check.

        Iterates over enclave-parent instances and reports whether hibernation
        is configured on the underlying EC2 instance.

        Returns:
            list[Check_Report_AWS]: One report per enclave-enabled instance.
        """
        findings = []
        for instance in ec2_client.instances:
            if not is_enclave_parent(instance):
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            if instance.hibernation_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} has hibernation "
                    f"enabled; RAM (which may contain enclave memory) can be serialized "
                    f"to EBS. AWS normally blocks this combination via "
                    f"InvalidParameterCombination, investigate this anomaly."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Nitro Enclave parent instance {instance.id} does not have "
                    f"hibernation enabled."
                )
            findings.append(report)
        return findings
