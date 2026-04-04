from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.stepfunctions.stepfunctions_client import (
    stepfunctions_client,
)


class stepfunctions_statemachine_no_secrets_in_definition(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = stepfunctions_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for state_machine in stepfunctions_client.state_machines.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=state_machine
            )
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Step Functions state machine {state_machine.name} definition."
            )

            if state_machine.definition:
                detect_secrets_output = detect_secrets_scan(
                    data=state_machine.definition,
                    excluded_secrets=secrets_ignore_patterns,
                    detect_secrets_plugins=stepfunctions_client.audit_config.get(
                        "detect_secrets_plugins",
                    ),
                )

                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Potential {'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                        f"found in Step Functions state machine {state_machine.name} definition "
                        f"-> {secrets_string}."
                    )

            findings.append(report)
        return findings
