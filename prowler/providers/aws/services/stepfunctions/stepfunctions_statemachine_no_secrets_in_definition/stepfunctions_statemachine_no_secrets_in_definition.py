from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.stepfunctions.stepfunctions_client import (
    stepfunctions_client,
)


class stepfunctions_statemachine_no_secrets_in_definition(Check):
    """Check that AWS Step Functions state machine definitions contain no hardcoded secrets."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = stepfunctions_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = stepfunctions_client.audit_config.get("secrets_validate", False)
        state_machines = list(stepfunctions_client.state_machines.values())

        # Collect one payload per state machine (its definition) and scan them
        # all in batched Kingfisher invocations instead of one subprocess each.
        def payloads():
            for index, state_machine in enumerate(state_machines):
                if state_machine.definition:
                    yield index, state_machine.definition

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, state_machine in enumerate(state_machines):
            report = Check_Report_AWS(metadata=self.metadata(), resource=state_machine)
            report.status = "PASS"
            report.status_extended = f"No secrets found in Step Functions state machine {state_machine.name} definition."

            if state_machine.definition:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Step Functions state machine "
                        f"{state_machine.name} definition for secrets: {scan_error}; "
                        "manual review is required."
                    )
                    findings.append(report)
                    continue
                detect_secrets_output = batch_results.get(index)
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
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)
        return findings
