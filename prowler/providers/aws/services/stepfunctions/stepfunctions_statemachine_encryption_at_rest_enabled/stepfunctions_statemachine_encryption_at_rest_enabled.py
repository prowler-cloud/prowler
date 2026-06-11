from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.stepfunctions.stepfunctions_client import (
    stepfunctions_client,
)
from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    EncryptionType,
)


class stepfunctions_statemachine_encryption_at_rest_enabled(Check):
    """Ensure Step Functions state machines are encrypted at rest with a customer-managed KMS key.

    This check evaluates whether each AWS Step Functions state machine uses a
    customer-managed KMS key (CUSTOMER_MANAGED_KMS_KEY) for encryption at rest rather
    than the default AWS-owned key (AWS_OWNED_KEY).

    - PASS: The state machine encryption_configuration type is CUSTOMER_MANAGED_KMS_KEY.
    - FAIL: The state machine has no encryption_configuration or its type is AWS_OWNED_KEY.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the Step Functions state machine encryption at rest check.

        Iterates over all Step Functions state machines and generates a report
        indicating whether each state machine uses a customer-managed KMS key
        for encryption at rest.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for state_machine in stepfunctions_client.state_machines.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=state_machine)

            if (
                state_machine.encryption_configuration
                and state_machine.encryption_configuration.type
                == EncryptionType.CUSTOMER_MANAGED_KMS_KEY
            ):
                report.status = "PASS"
                report.status_extended = f"Step Functions state machine {state_machine.name} is encrypted at rest with a customer-managed KMS key."
            else:
                report.status = "FAIL"
                report.status_extended = f"Step Functions state machine {state_machine.name} is not encrypted at rest with a customer-managed KMS key."

            findings.append(report)

        return findings
