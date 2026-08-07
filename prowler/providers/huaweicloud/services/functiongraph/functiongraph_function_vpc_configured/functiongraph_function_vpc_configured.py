from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.functiongraph.functiongraph_client import (
    functiongraph_client,
)


class functiongraph_function_vpc_configured(Check):
    """Check if FunctionGraph functions are configured within a VPC."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for function in functiongraph_client.functions:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=function,
            )
            report.region = function.region
            report.resource_id = function.function_id
            report.resource_arn = f"huaweicloud:functiongraph:{function.region}:{functiongraph_client.audited_account}:function/{function.function_id}"

            if function.func_vpc_id:
                report.status = "PASS"
                report.status_extended = f"Function '{function.name}' is configured within VPC '{function.func_vpc_id}'."
            else:
                report.status = "FAIL"
                report.status_extended = f"Function '{function.name}' is not associated with a VPC and has direct internet access without network restrictions."

            findings.append(report)

        return findings
