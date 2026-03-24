"""ASPM-062: AI agent execution environment must use pinned base images and versioned IaC."""

from prowler.lib.check.models import Check, CheckReportASPM
from prowler.providers.aspm.services.runtime.runtime_client import runtime_client


class aspm_agent_execution_environment_versioned(Check):
    """Check that AI agent execution environments use versioned, pinned base images.

    An unversioned execution environment cannot be reliably reproduced or
    audited.  Using floating tags (``latest``) or unversioned IaC means the
    runtime can silently change between deployments, making incident
    investigation and rollback unreliable.
    """

    def execute(self) -> list[CheckReportASPM]:
        """Execute the check against all loaded agents.

        Returns:
            A list of CheckReportASPM findings, one per agent.
        """
        findings = []
        for agent in runtime_client.agents:
            report = CheckReportASPM(metadata=self.metadata(), resource=agent)
            if not agent.runtime.execution_environment_versioned:
                report.status = "FAIL"
                report.status_extended = (
                    f"Agent {agent.name} execution environment is not versioned — "
                    "cannot reproduce or audit the runtime."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Agent {agent.name} execution environment uses pinned "
                    "base images and versioned IaC."
                )
            findings.append(report)
        return findings
