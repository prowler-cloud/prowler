from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.stepfunctions.stepfunctions_client import (
    stepfunctions_client,
)
from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    LoggingLevel,
)


class stepfunctions_statemachine_logging_enabled(Check):
    """
    Check if AWS Step Functions state machines have logging enabled.

    This class verifies whether each AWS Step Functions state machine has logging enabled by checking
    for the presence of a loggingConfiguration property in the state machine's configuration.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the Step Functions state machines logging enabled check.

        Iterates over all Step Functions state machines and generates a report indicating whether
        each state machine has logging enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for state_machine in stepfunctions_client.state_machines.values():
            report = Check_Report_AWS(self.metadata())
            report.region = state_machine.region
            report.resource_id = state_machine.id
            report.resource_arn = state_machine.arn
            report.resource_tags = state_machine.tags
            report.status = "PASS"
            report.status_extended = f"Step Functions state machine '{state_machine.name}' has logging enabled."

            if state_machine.logging_configuration.level == LoggingLevel.OFF:
                report.status = "FAIL"
                report.status_extended = f"Step Functions state machine '{state_machine.name}' does not have logging enabled."
            elif (
                stepfunctions_client.audit_config.get("statemachines_log_level")
                and stepfunctions_client.audit_config.get("statemachines_log_level")
                != state_machine.logging_configuration.level
            ):
                valid_config_value = any(
                    [
                        stepfunctions_client.audit_config.get("statemachines_log_level")
                        == e.value
                        for e in LoggingLevel
                    ]
                )

                if valid_config_value:
                    report.status = "FAIL"
                    report.status_extended = f"Step Functions state machine '{state_machine.name}' have the log level '{state_machine.logging_configuration.level.value}' which does not match the one specified in the configuration '{stepfunctions_client.audit_config.get('statemachines_log_level')}'."
                else:
                    report.status_extended = f"Invalid value found for statemachines_log_level parameter: {stepfunctions_client.audit_config.get('statemachines_log_level')}."

            findings.append(report)
        return findings
