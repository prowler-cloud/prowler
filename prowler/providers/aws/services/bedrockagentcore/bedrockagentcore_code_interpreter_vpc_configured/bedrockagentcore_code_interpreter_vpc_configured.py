from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_code_interpreter_vpc_configured(Check):
    """Ensure Bedrock AgentCore code interpreters do not use PUBLIC network mode.

    A code interpreter runs code the agent writes. PUBLIC mode gives it direct
    internet access, while VPC mode confines it to customer subnets and SANDBOX
    mode is isolated with no internet access (S3 only), so both pass.
    - PASS: The code interpreter uses VPC or SANDBOX network mode.
    - FAIL: The code interpreter uses PUBLIC network mode.
    - No finding: The AWS-owned built-in interpreter (aws.codeinterpreter.v1),
      which cannot be reconfigured, or a resource whose detail could not be read.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for interpreter in bedrockagentcore_client.code_interpreters.values():
            if not interpreter.detail_retrieved:
                continue  # unreadable: no finding, the service already logged the error
            if interpreter.arn.split(":")[4] != bedrockagentcore_client.audited_account:
                continue  # AWS-owned built-in: not configurable, never flag it
            report = Check_Report_AWS(metadata=self.metadata(), resource=interpreter)
            if interpreter.network_mode in ("VPC", "SANDBOX"):
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore code interpreter {interpreter.name} uses {interpreter.network_mode} network mode in region {interpreter.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore code interpreter {interpreter.name} uses {interpreter.network_mode or 'PUBLIC'} network mode instead of VPC or SANDBOX in region {interpreter.region}."
            findings.append(report)

        return findings
