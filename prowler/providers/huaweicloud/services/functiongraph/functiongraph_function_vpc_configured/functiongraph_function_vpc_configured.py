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

            if function.vpc_id:
                report.status = "PASS"
                report.status_extended = f"Function '{function.name}' is configured within VPC '{function.vpc_id}'."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Function '{function.name}' is not configured within a VPC."
                )

            findings.append(report)

        return findings
